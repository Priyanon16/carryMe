using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

// Auth (มีอยู่แล้ว)
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/admin/login.html";
        o.Cookie.Name = "carryme.auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
        o.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = ctx => {
                if (ctx.Request.Path.StartsWithSegments("/api")) { ctx.Response.StatusCode = 401; return Task.CompletedTask; }
                ctx.Response.Redirect(ctx.RedirectUri); return Task.CompletedTask;
            },
            OnRedirectToAccessDenied = ctx => {
                if (ctx.Request.Path.StartsWithSegments("/api")) { ctx.Response.StatusCode = 403; return Task.CompletedTask; }
                ctx.Response.Redirect(ctx.RedirectUri); return Task.CompletedTask;
            }
        };
    });

// ⬇️ สำคัญ: ต้องมีบรรทัดนี้
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("AdminOnly", p => p.RequireClaim("role", "admin"));
});

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();


// ---------- DB & Ensure ----------
string? cs = app.Configuration.GetConnectionString("Default")
            ?? "Data Source=carryme.db;Cache=Shared";

using (var conn = new SqliteConnection(cs))
{
    conn.Open();
    // ===== migrate: rebuild payments when legacy `order_id NOT NULL` exists =====
    try
    {
        using var check = new SqliteConnection(cs);
        check.Open();

        var hasLegacyOrderId = check.ExecuteScalar<long>(
            "SELECT COUNT(*) FROM pragma_table_info('payments') WHERE name='order_id' AND [notnull]=1");

        if (hasLegacyOrderId > 0)
        {
            using var tx = check.BeginTransaction();

            check.Execute("ALTER TABLE payments RENAME TO payments_old;", tx);

            check.Execute(@"
CREATE TABLE payments(
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  rider_id     INTEGER NOT NULL,
  amount       REAL    NOT NULL,
  slip_url     TEXT,
  status       TEXT    NOT NULL,
  note         TEXT,
  created_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  approved_at  TEXT,
  approved_by  TEXT
);", tx);

            check.Execute(@"
INSERT INTO payments (rider_id, amount, slip_url, status, note, created_at, approved_at, approved_by)
SELECT
    COALESCE(rider_id, 0),
    COALESCE(amount, 0),
    slip_url,
    COALESCE(status,'pending'),
    note,
    COALESCE(created_at, CURRENT_TIMESTAMP),
    approved_at,
    approved_by
FROM payments_old;", tx);

            check.Execute("DROP TABLE payments_old;", tx);

            tx.Commit();
        }
    }
    catch { /* ถ้าไม่มีตารางเดิม/ย้ายไม่สำเร็จ ให้ข้าม */ }


    // ตาราง riders
    conn.Execute(@"
CREATE TABLE IF NOT EXISTS riders(
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  name                TEXT,
  national_id         TEXT,
  vehicle_photo_url   TEXT,
  prb_doc_url         TEXT,
  national_id_card_url TEXT,
  address             TEXT,
  phone               TEXT,
  email               TEXT,
  username            TEXT UNIQUE,
  password_hash       TEXT,
  created_at          TEXT,
  is_approved         INTEGER DEFAULT 0,
  wallet              REAL DEFAULT 0,
  reject_reason       TEXT              -- ✅ เพิ่มคอลัมน์นี้ตรงนี้ (มีคอมมาก่อนหน้า)
);
");


    // ตาราง orders (ใส่ note ด้วย กัน error 'no such column: note')
    conn.Execute(@"
CREATE TABLE IF NOT EXISTS orders(
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  code                  TEXT UNIQUE,
  customer_name         TEXT,
  customer_phone        TEXT,
  items                 TEXT,
  shop                  TEXT,
  budget                REAL,
  dropoff               TEXT,
  desired_time          TEXT,
  note                  TEXT,
  rain                  INTEGER DEFAULT 0,
  zone_khamriang_over   INTEGER DEFAULT 0,
  zone_thakhonyang_over INTEGER DEFAULT 0,
  zone_frontuni_over    INTEGER DEFAULT 0,
  extra_stops_close     INTEGER DEFAULT 0,
  extra_stops_far       INTEGER DEFAULT 0,
  payment_method        TEXT,
  system_fee_percent    INTEGER,
  min_service           REAL,
  base_delivery         REAL,
  status                TEXT,
  created_at            TEXT,
  rider_id              INTEGER,
  actual_goods_cost     REAL,
  subtotal              REAL,
  platform_fee          REAL,
  rider_payout          REAL,
  pay_method            TEXT,
  pay_status            TEXT,
  cancel_reason         TEXT,
  cancel_note           TEXT
);");
    try { using var c = new SqliteConnection(cs); c.Execute("ALTER TABLE orders ADD COLUMN completed_at TEXT"); } catch { }
    try { using var c2 = new SqliteConnection(cs); c2.Execute("ALTER TABLE riders ADD COLUMN reject_reason TEXT;"); } catch { }
    // --- migrate: ensure payments has new columns ---
    try { conn.Execute("ALTER TABLE payments ADD COLUMN rider_id INTEGER"); } catch { }
    try { conn.Execute("ALTER TABLE payments ADD COLUMN amount REAL"); } catch { }
    try { conn.Execute("ALTER TABLE payments ADD COLUMN slip_url TEXT"); } catch { }
    try { conn.Execute("ALTER TABLE payments ADD COLUMN status TEXT"); } catch { }
    try { conn.Execute("ALTER TABLE payments ADD COLUMN note TEXT"); } catch { }
    try { conn.Execute("ALTER TABLE payments ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP"); } catch { }
    try { conn.Execute("ALTER TABLE payments ADD COLUMN approved_at TEXT"); } catch { }
    try { conn.Execute("ALTER TABLE payments ADD COLUMN approved_by TEXT"); } catch { }



    // ตาราง messages
    conn.Execute(@"
CREATE TABLE IF NOT EXISTS messages(
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id    INTEGER,
  sender_type TEXT,    -- customer/rider/system
  sender_name TEXT,
  rider_id    INTEGER,
  text        TEXT,
  created_at  TEXT
);");

    // ตาราง log อีเวนต์
    conn.Execute(@"
CREATE TABLE IF NOT EXISTS order_events(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id   INTEGER,
  actor      TEXT,
  event      TEXT,
  detail     TEXT,
  created_at TEXT
);");

    // ประวัติกระเป๋า
    conn.Execute(@"
CREATE TABLE IF NOT EXISTS wallet_tx(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rider_id INTEGER NOT NULL,
  amount   REAL NOT NULL,        -- + เติม / - หัก
  type     TEXT NOT NULL,        -- adjust/topup/payout/fee เป็นต้น
  note     TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);");

    // ตาราง payments สำหรับการเติมเงินแบบแนบสลิป (pending → approved/rejected)
    conn.Execute(@"
CREATE TABLE IF NOT EXISTS payments(
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  rider_id     INTEGER NOT NULL,
  amount       REAL NOT NULL,
  slip_url     TEXT,                 -- path รูปสลิปที่อัปโหลด
  status       TEXT NOT NULL,        -- pending/approved/rejected
  note         TEXT,                 -- เหตุผล/หมายเหตุ (ฝั่งแอดมิน)
  created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  approved_at  TEXT,                 -- เวลาอนุมัติ (ถ้า approved)
  approved_by  TEXT                  -- ชื่อแอดมิน (claim)
);");


    // ค่าธรรมเนียมระบบ
    conn.Execute(@"
CREATE TABLE IF NOT EXISTS fees(
  id INTEGER PRIMARY KEY CHECK (id=1),
  platform_rate REAL NOT NULL DEFAULT 0.10,   -- 10%
  base_delivery REAL NOT NULL DEFAULT 20,
  rain_surcharge REAL NOT NULL DEFAULT 10,
  updated_at TEXT
);
INSERT OR IGNORE INTO fees(id) VALUES(1);
");


    // seed บัญชีผู้รับหิ้วขั้นต่ำให้ลองใช้งาน
    if (conn.ExecuteScalar<int>("SELECT COUNT(*) FROM riders") == 0)
    {
        conn.Execute(@"INSERT INTO riders(name,username,password_hash,created_at,is_approved,wallet)
                       VALUES('Rider One','rider1',@hash,@ts,1,0)",
            new
            {
                hash = HashPassword("1234"),
                ts = DateTime.UtcNow.ToString("o")
            });
    }
}

// ---------- Helpers ----------
static string HashPassword(string password)
{
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    var hash = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256).GetBytes(32);
    return Convert.ToBase64String(salt.Concat(hash).ToArray());
}
static bool VerifyPassword(string password, string stored)
{
    var all = Convert.FromBase64String(stored);
    var salt = all[..16];
    var hash = all[16..];
    var test = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256).GetBytes(32);
    return CryptographicOperations.FixedTimeEquals(test, hash);
}
static double ReadDouble(JsonElement obj, string name, double def = 0)
{
    if (!obj.TryGetProperty(name, out var v)) return def;
    return v.ValueKind switch
    {
        JsonValueKind.Number => v.GetDouble(),
        JsonValueKind.String => double.TryParse(v.GetString(), out var d) ? d : def,
        _ => def
    };
}
static int ReadInt(JsonElement obj, string name, int def = 0)
{
    if (!obj.TryGetProperty(name, out var v)) return def;
    return v.ValueKind switch
    {
        JsonValueKind.Number => v.TryGetInt32(out var i) ? i : def,
        JsonValueKind.String => int.TryParse(v.GetString(), out var i2) ? i2 : def,
        _ => def
    };
}

// ======================= RIDER: Login/Logout =======================

app.MapPost("/api/riders/login", async (HttpContext ctx) =>
{
    try
    {
        var data = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(ctx.Request.Body);
        if (data is null || !data.TryGetValue("username", out var u) || !data.TryGetValue("password", out var p))
            return Results.Json(new { error = "ข้อมูลไม่ครบ" }, statusCode: 400);

        using var conn = new SqliteConnection(cs);
        var r = await conn.QuerySingleOrDefaultAsync(@"SELECT id,name,password_hash,is_approved FROM riders WHERE username=@u", new { u });
        if (r is null) return Results.Json(new { error = "ไม่พบบัญชี" }, statusCode: 401);
        if ((long)r.is_approved == 0) return Results.Json(new { error = "บัญชียังไม่ถูกอนุมัติ" }, statusCode: 403);
        if (!VerifyPassword(p, (string)r.password_hash)) return Results.Json(new { error = "รหัสผ่านผิด" }, statusCode: 401);

        var claims = new List<Claim> {
            new Claim(ClaimTypes.NameIdentifier, ((long)r.id).ToString()),
            new Claim(ClaimTypes.Name, (string)r.name),
            new Claim("rid", ((long)r.id).ToString()),
            new Claim("role", "rider")
        };
        await ctx.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
            new AuthenticationProperties { IsPersistent = true, ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7) });

        return Results.Json(new { ok = true, name = r.name });
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 500);
    }
});




app.MapPost("/api/riders/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Json(new { ok = true });
});

// ======================= RIDER: Register (multipart/form-data) =======================
app.MapPost("/api/riders/register", async (HttpContext ctx) =>
{
    try
    {
        var env = ctx.RequestServices.GetRequiredService<IWebHostEnvironment>();
        var form = await ctx.Request.ReadFormAsync();

        string? name = form["name"];
        string? nid = form["national_id"];
        string? addr = form["address"];
        string? phone = form["phone"];
        string? email = form["email"];
        string? user = form["username"];
        string? pass = form["password"];

        if (string.IsNullOrWhiteSpace(name) ||
            string.IsNullOrWhiteSpace(user) ||
            string.IsNullOrWhiteSpace(pass))
            return Results.BadRequest(new { error = "กรอกชื่อ / Username / Password ให้ครบ" });

        // path อัปโหลด
        var root = env.WebRootPath ?? Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");
        var updir = Path.Combine(root, "uploads");
        Directory.CreateDirectory(updir);

        // helper เซฟไฟล์
        static async Task<string?> SaveAsync(IFormFile? f, string dir)
        {
            if (f == null || f.Length == 0) return null;
            string ext = Path.GetExtension(f.FileName);
            string name = $"{Guid.NewGuid():N}{ext}";
            string full = Path.Combine(dir, name);
            await using var fs = File.Create(full);
            await f.CopyToAsync(fs);
            return "/uploads/" + name; // เก็บเป็นลิงก์สำหรับเสิร์ฟ
        }

        var files = form.Files;
        var vehicleUrl = await SaveAsync(files.GetFile("vehicle_photo"), updir);
        var prbUrl = await SaveAsync(files.GetFile("prb_doc"), updir);
        var idcardUrl = await SaveAsync(files.GetFile("national_id_card"), updir);

        using var conn = new SqliteConnection(cs);

        // กัน username ซ้ำ
        var exists = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM riders WHERE username=@u", new { u = user });
        if (exists > 0)
            return Results.Conflict(new { error = "Username นี้มีอยู่แล้ว" });

        await conn.ExecuteAsync(@"
INSERT INTO riders
(name, national_id, vehicle_photo_url, prb_doc_url, national_id_card_url,
 address, phone, email, username, password_hash, created_at, is_approved, wallet)
VALUES
(@name, @nid, @vehicleUrl, @prbUrl, @idcardUrl,
 @addr, @phone, @email, @user, @passHash, @ts, 0, 0)",
            new
            {
                name,
                nid,
                vehicleUrl,
                prbUrl,
                idcardUrl,
                addr,
                phone,
                email,
                user,
                passHash = HashPassword(pass!),
                ts = DateTime.UtcNow.ToString("o")
            });

        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        var msg = ex.Message.Contains("UNIQUE", StringComparison.OrdinalIgnoreCase)
            ? "Username นี้มีอยู่แล้ว"
            : ex.Message;
        return Results.Json(new { error = msg }, statusCode: 500);
    }
});



// ================ CUSTOMER: Create Order / View ================

app.MapPost("/api/orders", async (HttpRequest req) =>
{
    try
    {
        using var conn = new SqliteConnection(cs);
        using var doc = await JsonDocument.ParseAsync(req.Body);
        var r = doc.RootElement;

        string name = r.GetProperty("customer_name").GetString()!;
        string phone = r.GetProperty("customer_phone").GetString()!;
        string? items = r.TryGetProperty("items", out var it) ? it.GetString() : null;
        string? shop = r.TryGetProperty("shop", out var shp) ? shp.GetString() : null;
        double budget = ReadDouble(r, "budget", 0);
        string? dropoff = r.TryGetProperty("dropoff", out var d) ? d.GetString() : null;
        string? desiredTime = r.TryGetProperty("desired_time", out var dt) ? dt.GetString() : null;
        string? note = r.TryGetProperty("note", out var n) ? n.GetString() : null;

        bool rain = r.TryGetProperty("rain", out var rn) && rn.ValueKind == JsonValueKind.True;
        bool z1 = r.TryGetProperty("zone_khamriang_over", out var z1v) && z1v.ValueKind == JsonValueKind.True;
        bool z2 = r.TryGetProperty("zone_thakhonyang_over", out var z2v) && z2v.ValueKind == JsonValueKind.True;
        bool z3 = r.TryGetProperty("zone_frontuni_over", out var z3v) && z3v.ValueKind == JsonValueKind.True;

        int extraClose = ReadInt(r, "extra_stops_close", 0);
        int extraFar = ReadInt(r, "extra_stops_far", 0);

        string payMethod = r.TryGetProperty("pay_method", out var pm) ? (pm.GetString() ?? "system") : "system"; // system/cash
        int feePct = 5;

        long next = await conn.ExecuteScalarAsync<long>("SELECT IFNULL(MAX(id),0)+1 FROM orders");
        var code = $"A{next:000}";

        await conn.ExecuteAsync(@"
        INSERT INTO orders(code,customer_name,customer_phone,items,shop,budget,dropoff,desired_time,note,
            rain,zone_khamriang_over,zone_thakhonyang_over,zone_frontuni_over,
            extra_stops_close,extra_stops_far,payment_method,system_fee_percent,
            min_service,base_delivery,status,created_at,pay_method,pay_status)
        VALUES(@code,@name,@phone,@items,@shop,@budget,@dropoff,@desiredTime,@note,
            @rain,@z1,@z2,@z3,@extraClose,@extraFar,@payMethod,@feePct,100,20,'open',@ts,@payMethod,'unpaid')",
            new
            {
                code,
                name,
                phone,
                items,
                shop,
                budget,
                dropoff,
                desiredTime,
                note,
                rain,
                z1,
                z2,
                z3,
                extraClose,
                extraFar,
                payMethod,
                feePct,
                ts = DateTime.UtcNow.ToString("o")
            });

        return Results.Json(new { code });
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 500);
    }
});

app.MapGet("/api/orders/{code}", async (string code) =>
{
    using var conn = new SqliteConnection(cs);
    var o = await conn.QuerySingleOrDefaultAsync("SELECT * FROM orders WHERE code=@code", new { code });
    if (o is null) return Results.Json(new { error = "ไม่พบออเดอร์" }, statusCode: 404);

    var msgs = await conn.QueryAsync(
        "SELECT id,sender_type,sender_name,rider_id,text,created_at FROM messages WHERE order_id=@oid ORDER BY id ASC",
        new { oid = (long)o.id });

    return Results.Json(new { order = o, messages = msgs });
});

// =============== CUSTOMER CANCEL ===============
app.MapPost("/api/orders/{code}/cancel", async (string code, HttpRequest req) =>
{
    using var conn = new SqliteConnection(cs);

    dynamic? o = await conn.QuerySingleOrDefaultAsync(
        "SELECT id,status FROM orders WHERE code=@code", new { code });
    if (o is null) return Results.NotFound(new { error = "ไม่พบออเดอร์" });

    // ปิดทางยกเลิกหลังจบงาน
    string st = (string)o.status;
    if (st is "completed")
        return Results.BadRequest(new { error = "งานเสร็จแล้ว ยกเลิกไม่ได้" });

    using var doc = await JsonDocument.ParseAsync(req.Body);
    string? reason = doc.RootElement.TryGetProperty("reason", out var rv) ? rv.GetString() : null;
    string? note = doc.RootElement.TryGetProperty("note", out var nv) ? nv.GetString() : null;

    // เซ็ตสถานะยกเลิกโดยลูกค้า + เก็บเหตุผล
    await conn.ExecuteAsync(@"
        UPDATE orders
        SET status = 'cancelled_by_customer',
            cancel_reason = @reason,
            cancel_note = @note
        WHERE id = @id", new { reason, note, id = (long)o.id });

    // บันทึกข้อความระบบ (เผื่อหน้าอื่นต้องการแสดงประวัติ)
    await conn.ExecuteAsync(@"
        INSERT INTO messages(order_id, sender_type, sender_name, text, created_at)
        VALUES(@oid,'system','system','ลูกค้ายกเลิกออเดอร์',@ts)",
        new { oid = (long)o.id, ts = DateTime.UtcNow.ToString("o") });

    return Results.Ok(new { ok = true });
});


// ====================== RIDER: Dashboard / Orders ======================

app.MapGet("/api/rider/summary", async (HttpContext ctx) =>
{
    // ต้องเป็นผู้รับหิ้วเท่านั้น
    var role = ctx.User.FindFirst("role")?.Value;
    if (!(ctx.User?.Identity?.IsAuthenticated ?? false) || role != "rider")
        return Results.Json(new { error = "unauthorized" }, statusCode: 401);

    var ridClaim = ctx.User.FindFirst("rid")?.Value;
    if (!long.TryParse(ridClaim, out var rid))
        return Results.Json(new { error = "unauthorized" }, statusCode: 401);

    using var conn = new SqliteConnection(cs);
    var open = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM orders WHERE status='open'");
    var active = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM orders WHERE rider_id=@rid AND status IN('claimed','ongoing')", new { rid });

    var earningToday = await conn.ExecuteScalarAsync<double>(
        @"SELECT IFNULL(SUM(rider_payout),0) FROM orders
          WHERE rider_id=@rid AND status='completed'
            AND date(completed_at)=date('now')", new { rid });

    var onlineMinutes = 120; // mock
    return Results.Json(new { open, active, earning_today = earningToday, online_minutes = onlineMinutes });
});


// งานใหม่
app.MapGet("/api/rider/orders/new", async () =>
{
    using var conn = new SqliteConnection(cs);
    var rows = await conn.QueryAsync(@"
        SELECT code, customer_name, shop, dropoff, budget, status
        FROM orders WHERE status='open' ORDER BY id DESC LIMIT 50");
    return Results.Json(rows);
});

// งานของฉัน
app.MapGet("/api/rider/orders/mine", async (HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true) return Results.Json(new { error = "unauthorized" }, statusCode: 401);
    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);
    using var conn = new SqliteConnection(cs);
    var rows = await conn.QueryAsync(@"
        SELECT code, shop, dropoff, budget, status
        FROM orders WHERE rider_id=@rid AND status IN('claimed','ongoing') ORDER BY id DESC", new { rid });
    return Results.Json(rows);
});

// ประวัติ
app.MapGet("/api/rider/orders/history", async (HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true) return Results.Json(new { error = "unauthorized" }, statusCode: 401);
    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);
    using var conn = new SqliteConnection(cs);
    var rows = await conn.QueryAsync(@"
        SELECT code, shop, dropoff, budget, status
        FROM orders
        WHERE rider_id=@rid AND status IN('completed','cancelled_by_customer','cancelled_by_rider')
        ORDER BY id DESC LIMIT 50", new { rid });
    return Results.Json(rows);
});

// รับงาน
app.MapPost("/api/rider/orders/{code}/claim", async (string code, HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true) return Results.Json(new { error = "unauthorized" }, statusCode: 401);
    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);
    using var conn = new SqliteConnection(cs);

    var approved = await conn.ExecuteScalarAsync<long>("SELECT is_approved FROM riders WHERE id=@rid", new { rid });
    if (approved == 0) return Results.Json(new { error = "บัญชียังไม่ถูกอนุมัติ" }, statusCode: 403);


    var o = await conn.QuerySingleOrDefaultAsync("SELECT id,status FROM orders WHERE code=@code", new { code });
    if (o is null) return Results.Json(new { error = "ไม่พบงาน" }, statusCode: 404);
    if ((string)o.status != "open") return Results.Json(new { error = "มีคนรับงานนี้แล้ว" }, statusCode: 400);

    await conn.ExecuteAsync("UPDATE orders SET status='claimed', rider_id=@rid WHERE id=@id", new { rid, id = (long)o.id });
    return Results.Json(new { ok = true });
});

// เริ่มงาน
app.MapPost("/api/rider/orders/{code}/start", async (string code, HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true) return Results.Json(new { error = "unauthorized" }, statusCode: 401);
    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);
    using var conn = new SqliteConnection(cs);
    var o = await conn.QuerySingleOrDefaultAsync("SELECT id,status,rider_id FROM orders WHERE code=@code", new { code });
    if (o is null) return Results.Json(new { error = "ไม่พบงาน" }, statusCode: 404);
    if ((long?)o.rider_id != rid) return Results.Json(new { error = "forbidden" }, statusCode: 403);
    if ((string)o.status != "claimed") return Results.Json(new { error = "สถานะไม่ถูกต้อง" }, statusCode: 400);

    await conn.ExecuteAsync("UPDATE orders SET status='ongoing' WHERE id=@id", new { id = (long)o.id });
    return Results.Json(new { ok = true });
});

// เสร็จงาน
app.MapPost("/api/rider/orders/{code}/complete", async (string code, HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true) return Results.Json(new { error = "unauthorized" }, statusCode: 401);
    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);

    using var conn = new SqliteConnection(cs);
    var o = await conn.QuerySingleOrDefaultAsync("SELECT * FROM orders WHERE code=@code", new { code });
    if (o is null) return Results.Json(new { error = "ไม่พบงาน" }, statusCode: 404);
    if ((long?)o.rider_id != rid) return Results.Json(new { error = "forbidden" }, statusCode: 403);
    if ((string)o.status is not ("ongoing" or "claimed")) return Results.Json(new { error = "สถานะไม่ถูกต้อง" }, statusCode: 400);

    // ถ้ายังไม่ได้คำนวณ rider_payout (ยัง null) ให้คำนวณจาก Calc แล้วอัปเดต
    if (o.rider_payout is null)
    {
        var (delivery, service, goods, subtotal, platform, payout) = Calc(o);
        await conn.ExecuteAsync(
            "UPDATE orders SET subtotal=@sub, platform_fee=@pf, rider_payout=@rp WHERE id=@id",
            new { sub = subtotal, pf = platform, rp = payout, id = (long)o.id });
    }

    await conn.ExecuteAsync(
        "UPDATE orders SET status='completed', completed_at=@ts WHERE id=@id",
        new { id = (long)o.id, ts = DateTime.UtcNow.ToString("o") });

    // ให้แน่ใจว่ามี subtotal แล้ว ถ้าใน o ยังไม่มี ให้คำนวณจาก Calc(o)
    double subtotalVal;
    if (o.subtotal is null)
    {
        var t = Calc(o);
        subtotalVal = t.subtotal;
        await conn.ExecuteAsync(
            "UPDATE orders SET subtotal=@sub, platform_fee=@pf, rider_payout=@rp WHERE id=@id",
            new { sub = t.subtotal, pf = t.platform, rp = t.payout, id = (long)o.id });
    }
    else
    {
        subtotalVal = (double)o.subtotal;
    }

    // ✅ หักค่าธรรมเนียม 5% จาก wallet ของไรเดอร์ และลงประวัติ
    double feeToCharge = Math.Round(subtotalVal * 0.05, 2);
    await conn.ExecuteAsync(
        "UPDATE riders SET wallet = wallet - @fee WHERE id=@rid",
        new { fee = feeToCharge, rid });

    await conn.ExecuteAsync(@"
    INSERT INTO wallet_tx(rider_id, amount, type, note)
    VALUES(@rid, -@fee, 'fee', 'หักค่าธรรมเนียม 5% ของออเดอร์ " + code + @"')",
        new { rid, fee = feeToCharge });

    return Results.Json(new { ok = true });
});

// ยกเลิกโดยผู้รับหิ้ว
app.MapPost("/api/rider/orders/{code}/cancel", async (string code, HttpContext ctx, HttpRequest req) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true) return Results.Json(new { error = "unauthorized" }, statusCode: 401);
    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);
    using var conn = new SqliteConnection(cs);
    var o = await conn.QuerySingleOrDefaultAsync("SELECT id,status,rider_id FROM orders WHERE code=@code", new { code });
    if (o is null) return Results.Json(new { error = "ไม่พบงาน" }, statusCode: 404);
    if ((long?)o.rider_id != rid) return Results.Json(new { error = "forbidden" }, statusCode: 403);

    using var doc = await JsonDocument.ParseAsync(req.Body);
    var reason = doc.RootElement.TryGetProperty("reason", out var rv) ? rv.GetString() : null;

    await conn.ExecuteAsync("UPDATE orders SET status='cancelled_by_rider', cancel_reason=@r WHERE id=@id",
        new { r = reason, id = (long)o.id });
    return Results.Json(new { ok = true });
});

// อัปเดตสถานะช่วงทำงาน (going/bought) + แชท system
app.MapPost("/api/rider/orders/{code}/status", async (string code, HttpContext ctx, HttpRequest req) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true) return Results.Json(new { error = "unauthorized" }, statusCode: 401);
    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);
    using var conn = new SqliteConnection(cs);
    var oid = await conn.ExecuteScalarAsync<long?>("SELECT id FROM orders WHERE code=@code AND rider_id=@rid", new { code, rid });
    if (oid is null) return Results.Json(new { error = "forbidden" }, statusCode: 403);

    using var doc = await JsonDocument.ParseAsync(req.Body);
    var action = doc.RootElement.TryGetProperty("action", out var av) ? av.GetString() : null;
    string msg = action switch
    {
        "going" => "ผู้รับหิ้วกำลังไปซื้อของ",
        "bought" => "ผู้รับหิ้วซื้อของเสร็จแล้ว",
        _ => "อัปเดตสถานะ"
    };

    await conn.ExecuteAsync(@"
      INSERT INTO messages(order_id,sender_type,sender_name,text,created_at)
      VALUES(@oid,'system','system',@msg,@ts)",
      new { oid = (long)oid, msg, ts = DateTime.UtcNow.ToString("o") });

    return Results.Json(new { ok = true });
});

// ผู้รับหิ้ว "แจ้งยอด" : บันทึกราคาสินค้าจริง + เงื่อนไขเพิ่ม และส่งข้อความแจ้งยอดรวม (ไทย)
app.MapPost("/api/rider/orders/{code}/finalize", async (string code, HttpContext ctx, HttpRequest req) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();

    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);

    using var conn = new SqliteConnection(
        ctx.RequestServices.GetRequiredService<IConfiguration>().GetConnectionString("Default"));

    var o = await conn.QuerySingleOrDefaultAsync("SELECT id,rider_id FROM orders WHERE code=@code", new { code });
    if (o is null) return Results.NotFound("ไม่พบออเดอร์");
    if ((long?)o.rider_id != rid) return Results.Forbid();

    using var doc = await JsonDocument.ParseAsync(req.Body);
    var root = doc.RootElement;

    double goods = root.TryGetProperty("goods_cost", out var gv) && gv.ValueKind == JsonValueKind.Number ? gv.GetDouble() : 0;
    bool rain = root.TryGetProperty("rain", out var rv) && rv.ValueKind == JsonValueKind.True;
    bool z1 = (root.TryGetProperty("z1", out var z1v) && z1v.ValueKind == JsonValueKind.True) ||
                (root.TryGetProperty("zone_khamriang_over", out var z1v2) && z1v2.ValueKind == JsonValueKind.True);
    bool z2 = (root.TryGetProperty("z2", out var z2v) && z2v.ValueKind == JsonValueKind.True) ||
                (root.TryGetProperty("zone_thakhonyang_over", out var z2v2) && z2v2.ValueKind == JsonValueKind.True);
    bool z3 = (root.TryGetProperty("z3", out var z3v) && z3v.ValueKind == JsonValueKind.True) ||
                (root.TryGetProperty("zone_frontuni_over", out var z3v2) && z3v2.ValueKind == JsonValueKind.True);

    // อัปเดตธงและราคาสินค้าจริง
    await conn.ExecuteAsync(@"
        UPDATE orders
        SET actual_goods_cost = @goods,
            rain = @rain,
            zone_khamriang_over = @z1,
            zone_thakhonyang_over = @z2,
            zone_frontuni_over   = @z3
        WHERE id = @id",
        new { goods, rain, z1, z2, z3, id = (long)o.id });

    // คำนวณยอดรวม (ใช้ฟังก์ชัน Calc ที่มีอยู่แล้วในไฟล์)
    var full = await conn.QuerySingleAsync("SELECT * FROM orders WHERE id=@id", new { id = (long)o.id });

    (double delivery,
     double service,
     double _goods,
     double subtotal,
     double platform,
     double payout) = Calc(full);


    // (ออปชัน) เก็บค่าไว้ที่ออเดอร์ด้วย เพื่อหน้าอื่นอ่านซ้ำได้เร็ว
    await conn.ExecuteAsync(@"
        UPDATE orders SET subtotal=@sub, platform_fee=@pf, rider_payout=@rp
        WHERE id=@id",
        new { sub = subtotal, pf = platform, rp = payout, id = (long)o.id });

    // สร้างข้อความไทยอ่านง่าย (แทน Z1/Z2/Z3)
    string opts = string.Join(" / ", new[]
    {
        rain ? "ฝนตก(+10)" : null,
        z1 ? "ข้ามโซน ขามเรียง(+10)" : null,
        z2 ? "ข้ามโซน ท่าขอนยาง(+10)" : null,
        z3 ? "ข้ามโซน หน้า มมส(+10)" : null
    }.Where(s => s != null));

    if (string.IsNullOrEmpty(opts)) opts = "ไม่มีเงื่อนไขเพิ่ม";

    var msg = $"ผู้รับหิ้วแจ้งยอดเบื้องต้น: ค่าสินค้า {goods:0} บ. + ค่าส่ง {delivery:0} บ. + {opts} = รวม {subtotal:0} บ.";

    await conn.ExecuteAsync(@"
        INSERT INTO messages(order_id, sender_type, sender_name, text, created_at)
        VALUES(@oid,'system','system',@msg,@ts)",
        new { oid = (long)o.id, msg, ts = DateTime.UtcNow.ToString("o") });

    return Results.Ok(new { ok = true, subtotal, platform_fee = platform, rider_payout = payout });
});


// ========================== RIDER WALLET ==========================
// อ่านยอดกระเป๋า (ต้องล็อกอินเป็น rider)
app.MapGet("/api/rider/wallet", async (HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Json(new { error = "unauthorized" }, statusCode: 401);

    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);
    using var conn = new SqliteConnection(app.Configuration.GetConnectionString("Default"));
    var bal = await conn.ExecuteScalarAsync<double>("SELECT wallet FROM riders WHERE id=@rid", new { rid });
    return Results.Json(new { wallet = bal });
});

// เติมเครดิตแบบแนบสลิป (รออนุมัติ) — multipart/form-data
// fields: amount (number), slip (file)
app.MapPost("/api/rider/wallet/topup", async (HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Json(new { error = "unauthorized" }, statusCode: 401);

    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);

    var form = await ctx.Request.ReadFormAsync();
    if (!double.TryParse(form["amount"], out var amount) || amount <= 0)
        return Results.BadRequest(new { error = "กรอกจำนวนเงินให้ถูกต้อง" });

    // เซฟไฟล์สลิป (ถ้ามี)
    var env = ctx.RequestServices.GetRequiredService<IWebHostEnvironment>();
    var root = env.WebRootPath ?? Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");
    var updir = Path.Combine(root, "uploads");
    Directory.CreateDirectory(updir);

    string? slipUrl = null;
    var slip = form.Files.GetFile("slip");
    if (slip is not null && slip.Length > 0)
    {
        var ext = Path.GetExtension(slip.FileName);
        var fn = $"{Guid.NewGuid():N}{ext}";
        var full = Path.Combine(updir, fn);
        await using var fs = File.Create(full);
        await slip.CopyToAsync(fs);
        slipUrl = "/uploads/" + fn;
    }

    using var conn = new SqliteConnection(cs);
    await conn.ExecuteAsync(@"
        INSERT INTO payments(rider_id, amount, slip_url, status, note)
        VALUES(@rid, @amount, @slip, 'pending', NULL)",
        new { rid, amount, slip = slipUrl });

    return Results.Ok(new { ok = true });
});

// อ่านรายการคำขอเติมเครดิตของไรเดอร์ (pending/approved/rejected)
app.MapGet("/api/rider/wallet/topups", async (HttpContext ctx) =>
{
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Json(new { error = "unauthorized" }, statusCode: 401);

    var rid = long.Parse(ctx.User.FindFirst("rid")!.Value);

    using var conn = new SqliteConnection(cs);
    var rows = await conn.QueryAsync(@"
        SELECT id, amount, slip_url, status, note, created_at, approved_at
        FROM payments
        WHERE rider_id = @rid
        ORDER BY id DESC
        LIMIT 50", new { rid });

    return Results.Ok(rows);
});


// ======================== END RIDER WALLET ========================

// ===================== PRICE CALCULATOR =====================
// คืนค่า: ค่าส่ง(ฐาน), ค่าบริการ, ค่าสินค้าจริง, ยอดรวม, ค่าธรรมเนียมระบบ, เงินสุทธิไรเดอร์
static (double delivery, double service, double goods, double subtotal, double platform, double payout) Calc(dynamic o)
{
    // ฐานค่าส่ง = 10 บาทคงที่
    double baseDelivery = 10d;

    // ไม่คิดค่าบริการ
    double service = 0;
    int feePct = (int)(o.system_fee_percent ?? 5);

    // ธงเงื่อนไข
    bool rain = o.rain is long rl ? rl == 1 : o.rain is int ri ? ri == 1 : (o.rain is bool rb && rb);
    bool z1 = o.zone_khamriang_over is long z1l ? z1l == 1 : o.zone_khamriang_over is int z1i ? z1i == 1 : (o.z1 is bool z1b && z1b);
    bool z2 = o.zone_thakhonyang_over is long z2l ? z2l == 1 : o.zone_thakhonyang_over is int z2i ? z2i == 1 : (o.z2 is bool z2b && z2b);
    bool z3 = o.zone_frontuni_over is long z3l ? z3l == 1 : o.zone_frontuni_over is int z3i ? z3i == 1 : (o.z3 is bool z3b && z3b);

    int extraClose = (int)(o.extra_stops_close ?? 0);
    int extraFar = (int)(o.extra_stops_far ?? 0);

    // เงื่อนไขเพิ่มเติม (อยู่นี่)
    double extra = (rain ? 10 : 0)
                 + (z1 ? 10 : 0)
                 + (z2 ? 10 : 0)
                 + (z3 ? 10 : 0)
                 + extraClose * 5
                 + extraFar * 10;

    double delivery = baseDelivery;                  // << ค่าส่งฐานอย่างเดียว
    double goods = (double)(o.actual_goods_cost ?? 0d);

    double subtotal = goods + delivery + extra;      // รวมที่นี่
    double platform = Math.Round(subtotal * feePct / 100.0, 2);
    double payout = subtotal - platform;

    return (delivery, service, goods, subtotal, platform, payout);
}



// ============= PAYMENT (Quote + Confirm) =============

// ส่งยอดที่ต้องจ่าย (รวม extra ให้หน้า order.html)
app.MapGet("/api/pay/quote/{code}", async (string code) =>
{
    try
    {
        using var conn = new SqliteConnection(cs);
        dynamic? o = await conn.QuerySingleOrDefaultAsync(
            "SELECT * FROM orders WHERE code=@code", new { code });
        if (o is null) return Results.NotFound(new { error = "ไม่พบบอเดอร์" });

        var (delivery, service, goods, subtotal, platform, payout) = Calc(o);

        // คำนวณ extra จากธงเงื่อนไขโดยตรง
        bool rain = o.rain == 1 || (o.rain is bool rb && rb);
        bool z1 = o.zone_khamriang_over == 1;
        bool z2 = o.zone_thakhonyang_over == 1;
        bool z3 = o.zone_frontuni_over == 1;
        int exC = (int)(o.extra_stops_close ?? 0);
        int exF = (int)(o.extra_stops_far ?? 0);

        double extra = (rain ? 10 : 0)
                     + (z1 ? 10 : 0)
                     + (z2 ? 10 : 0)
                     + (z3 ? 10 : 0)
                     + exC * 5
                     + exF * 10;

        return Results.Ok(new
        {
            code = (string)o.code,
            delivery,    // 10
            goods,
            extra,       // เงื่อนไขเพิ่มเติมทั้งหมด
            subtotal,    // goods + delivery + extra
            rain,
            z1,
            z2,
            z3
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 500);

    }
});

app.MapPost("/api/admin/login", async (HttpContext ctx) =>
{
    using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
    var u = doc.RootElement.GetProperty("username").GetString();
    var p = doc.RootElement.GetProperty("password").GetString();

    // ตัวอย่างทดสอบ: admin/1234 (ภายหลังเปลี่ยนเป็นตรวจ DB จริง)
    if (u == "admin" && p == "1234")
    {
        var claims = new List<Claim>{
            new Claim(ClaimTypes.Name, "carryMe Admin"),
            new Claim("role","admin")
        };
        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
        return Results.Ok(new { ok = true });
    }
    return Results.Unauthorized();
});

app.MapPost("/api/admin/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok();
});


var admin = app.MapGroup("/api/admin").RequireAuthorization("AdminOnly");


// 1) รายการผู้รับหิ้วที่รออนุมัติ
admin.MapGet("/riders/pending", async () =>
{
    using var c = new SqliteConnection(cs);
    var sql = @"
        SELECT id, name, phone, username, created_at,
               wallet, is_approved
        FROM riders
        WHERE is_approved = 0
          AND (reject_reason IS NULL OR TRIM(reject_reason) = '')
        ORDER BY created_at DESC";
    return Results.Ok(await c.QueryAsync(sql));
});


admin.MapGet("/riders/rejected", async () =>
{
    using var c = new SqliteConnection(cs);
    var sql = @"
        SELECT id, name, phone, username, created_at, reject_reason
        FROM riders
        WHERE is_approved = 0
          AND (reject_reason IS NOT NULL AND TRIM(reject_reason) <> '')
        ORDER BY id DESC";
    return Results.Ok(await c.QueryAsync(sql));
});


// 2) อนุมัติผู้รับหิ้ว
admin.MapPost("/riders/{id:int}/approve", async (int id) =>
{
    using var c = new SqliteConnection(cs);
    await c.ExecuteAsync(
        "UPDATE riders SET is_approved = 1, reject_reason = NULL WHERE id = @id",
        new { id });
    return Results.Ok(new { message = "อนุมัติแล้ว" });
});


// 3) ปฏิเสธ / ระงับผู้รับหิ้ว

// ปฏิเสธ/ระงับ พร้อมบันทึกเหตุผล
admin.MapPost("/riders/{id:int}/reject", async (int id, RejectDto dto) =>
{
    if (dto is null || string.IsNullOrWhiteSpace(dto.Reason))
        return Results.BadRequest(new { error = "กรุณาใส่เหตุผลในการปฏิเสธ" });

    using var c = new SqliteConnection(cs);
    var rows = await c.ExecuteAsync(@"
        UPDATE riders
        SET is_approved = 0,
            reject_reason = @Reason
        WHERE id = @id", new { id, dto.Reason });

    return rows > 0
        ? Results.Ok(new { message = "ปฏิเสธแล้ว", reason = dto.Reason })
        : Results.NotFound(new { error = "ไม่พบบัญชี" });
});




admin.MapDelete("/riders/{id:int}", async (int id) =>
{
    using var c = new SqliteConnection(cs);
    await c.ExecuteAsync("DELETE FROM riders WHERE id=@id", new { id });
    return Results.Ok(new { message = "ลบแล้ว" });
});

// 3) รายการฝากหิ้ว/รับหิ้ว
admin.MapGet("/orders", async (string? status) =>
{
    using var c = new SqliteConnection(cs);
    var sql = @"SELECT o.id, o.code, o.status, 
                       o.subtotal AS total, o.created_at,
                       o.rider_id, (SELECT name FROM riders r WHERE r.id=o.rider_id) AS rider_name
                FROM orders o
                WHERE (@status IS NULL OR o.status=@status)
                ORDER BY o.created_at DESC";
    return Results.Ok(await c.QueryAsync(sql, new { status }));
});


// 4) กระเป๋าตังค์ผู้รับหิ้ว (ใช้ field wallet ในตาราง riders)
admin.MapGet("/wallets", async () =>
{
    using var c = new SqliteConnection(cs);
    var sql = "SELECT id AS riderId, name, wallet AS balance FROM riders ORDER BY id";
    return Results.Ok(await c.QueryAsync(sql));
});

admin.MapGet("/wallets/{riderId:int}/tx", async (int riderId) =>
{
    using var c = new SqliteConnection(cs);
    var sql = "SELECT id, rider_id AS riderId, amount, type, note, created_at FROM wallet_tx WHERE rider_id=@r ORDER BY id DESC";
    return Results.Ok(await c.QueryAsync(sql, new { r = riderId }));
});

// ปรับยอดกระเป๋าเงิน + ลงประวัติให้ถูกต้อง
admin.MapPost("/wallets/adjust", async (WalletAdjustDto body) =>
{
    if (body.Amount == 0) return Results.BadRequest(new { error = "Amount ต้องไม่เป็น 0" });

    using var c = new SqliteConnection(cs);
    await c.OpenAsync(); // <<< สำคัญ: ต้องเปิดก่อน BeginTransaction/Execute

    using var tx = c.BeginTransaction();

    // เช็คว่ามี Rider นี้จริง
    var exists = await c.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM riders WHERE id=@id", new { id = body.RiderId }, tx);
    if (exists == 0) return Results.NotFound(new { error = "ไม่พบ Rider" });

    // ปรับยอด
    await c.ExecuteAsync("UPDATE riders SET wallet = wallet + @a WHERE id=@r",
        new { a = body.Amount, r = body.RiderId }, tx);

    // ลงประวัติ
    await c.ExecuteAsync(@"INSERT INTO wallet_tx(rider_id,amount,type,note,created_at)
                           VALUES(@r,@a,@type,@note,CURRENT_TIMESTAMP)",
        new { r = body.RiderId, a = body.Amount, type = body.Type ?? "adjust", note = body.Note }, tx);

    tx.Commit();

    var bal = await c.ExecuteScalarAsync<double>("SELECT wallet FROM riders WHERE id=@r", new { r = body.RiderId });
    return Results.Ok(new { ok = true, balance = bal });
});


// 5) ค่าธรรมเนียม
admin.MapGet("/fees", async () =>
{
    using var c = new SqliteConnection(cs);
    return Results.Ok(await c.QuerySingleAsync("SELECT id, platform_rate, base_delivery, rain_surcharge FROM fees WHERE id=1"));
});

admin.MapPost("/fees", async (FeeDto f) =>
{
    using var c = new SqliteConnection(cs);
    await c.ExecuteAsync(@"UPDATE fees SET platform_rate=@PlatformRate, base_delivery=@BaseDelivery, rain_surcharge=@RainSurcharge, updated_at=CURRENT_TIMESTAMP WHERE id=1", f);
    return Results.Ok(new { message = "บันทึกค่าธรรมเนียมแล้ว" });
});

// สรุปตัวเลขบนการ์ด
admin.MapGet("/stats", async () =>
{
    using var c = new SqliteConnection(cs);
    var sql = @"
      SELECT
        -- รออนุมัติ: is_approved=0 และไม่มีเหตุผลปฏิเสธ
        (SELECT COUNT(*) FROM riders
           WHERE is_approved=0
             AND (reject_reason IS NULL OR TRIM(reject_reason)='')) AS pending_riders,

        (SELECT COUNT(*) FROM riders WHERE is_approved=1) AS approved_riders,
        (SELECT COUNT(*) FROM orders) AS total_orders,
        (SELECT IFNULL(SUM(platform_fee),0) FROM orders) AS platform_earnings
    ";
    return Results.Ok(await c.QuerySingleAsync(sql));
});


// รายการผู้รับหิ้ว (พร้อมตัวกรองสถานะ)
admin.MapGet("/riders/list", async (string? approved, string? q) =>
{
    // แปลงค่า approved จาก string → int? (ถ้า approved เป็น "" หรือ null จะกลายเป็น null)
    int? approvedVal = int.TryParse(approved, out var tmp) ? tmp : (int?)null;

    using var c = new SqliteConnection(cs);
    var rows = await c.QueryAsync(@"
        SELECT id, name, phone, email, username, address, created_at, is_approved, wallet
        FROM riders
        WHERE (@approved IS NULL OR is_approved = @approved)
          AND (@q IS NULL OR name LIKE '%'||@q||'%' OR phone LIKE '%'||@q||'%' OR username LIKE '%'||@q||'%')
        ORDER BY id DESC",
        new { approved = approvedVal, q });

    return Results.Ok(rows);
});

// รายการออเดอร์แบบย่อ (มีตัวกรองสถานะ)
admin.MapGet("/orders/list", async (string? status) =>
{
    using var c = new SqliteConnection(cs);
    var rows = await c.QueryAsync(@"
        SELECT id, code, status, customer_name, shop, dropoff,
               created_at, subtotal, platform_fee,
               rider_id, (SELECT name FROM riders r WHERE r.id=o.rider_id) AS rider_name
        FROM orders o
        WHERE (@status IS NULL OR status=@status)
        ORDER BY id DESC LIMIT 200", new { status });
    return Results.Ok(rows);
});

// แก้ไขสถานะออเดอร์อย่างเร็ว (คงไว้เหมือนเดิมก็ได้)
admin.MapPost("/orders/{id:int}/status", async (int id, OrderStatusDto body) =>
{
    using var c = new SqliteConnection(cs);
    await c.ExecuteAsync("UPDATE orders SET status=@Status WHERE id=@Id", new { Id = id, body.Status });
    return Results.Ok(new { message = "อัปเดตแล้ว" });
});

// ดึงข้อมูลรายคน
admin.MapGet("/riders/{id:int}", async (int id) =>
{
    using var c = new SqliteConnection(cs);
    var row = await c.QuerySingleOrDefaultAsync("SELECT * FROM riders WHERE id=@id", new { id });
    return row is null ? Results.NotFound() : Results.Ok(row);
});

// อัปเดตข้อมูล
admin.MapPut("/riders/{id:int}", async (int id, RiderEditDto body) =>
{
    using var c = new SqliteConnection(cs);
    await c.ExecuteAsync(@"UPDATE riders
                           SET name=@Name, phone=@Phone, email=@Email, username=@Username, address=@Address, is_approved=@Is_Approved
                           WHERE id=@Id",
                           new
                           {
                               Id = id,
                               body.Name,
                               body.Phone,
                               body.Email,
                               body.Username,
                               body.Address,
                               body.Is_Approved
                           });
    return Results.Ok(new { message = "บันทึกสำเร็จ" });
});

// รายละเอียดผู้รับหิ้ว (สำหรับหน้า Modal)
admin.MapGet("/riders/{id:int}/detail", async (int id) =>
{
    using var c = new SqliteConnection(cs);
    var sql = @"
        SELECT id, name, phone, email, username, address, created_at,
               is_approved, wallet,
               reject_reason,                         -- << เพิ่มบรรทัดนี้
               vehicle_photo_url, prb_doc_url, national_id_card_url
        FROM riders
        WHERE id = @id";
    var row = await c.QuerySingleOrDefaultAsync(sql, new { id });
    return row is null ? Results.NotFound() : Results.Ok(row);
});


// แก้ไขข้อมูลผู้รับหิ้ว (จากหน้า Modal)
admin.MapPost("/riders/{id:int}/edit", async (int id, RiderEditDto body) =>
{
    using var c = new SqliteConnection(cs);
    await c.ExecuteAsync(@"
        UPDATE riders SET
          name = @Name,
          phone = @Phone,
          email = @Email,
          username = @Username,
          address = @Address,
          is_approved = @Is_Approved
        WHERE id=@Id", new
    {
        Id = id,
        body.Name,
        body.Phone,
        body.Email,
        body.Username,
        body.Address,
        body.Is_Approved
    });
    return Results.Ok(new { message = "บันทึกสำเร็จ" });
});

// DTO สำหรับแก้ไข

// ===== Admin: จัดการคำขอเติมเครดิต (Topups) =====

// ลิสต์คำขอ (กรองสถานะได้: pending/approved/rejected; ไม่ส่ง = ทั้งหมด)
admin.MapGet("/topups", async (string? status) =>
{
    using var c = new SqliteConnection(cs);
    var rows = await c.QueryAsync(@"
      SELECT p.id,
             p.rider_id,
             (SELECT name FROM riders r WHERE r.id = p.rider_id) AS rider_name,
             p.amount, p.slip_url, p.status, p.note, p.created_at, p.approved_at, p.approved_by
      FROM payments p
      WHERE (@status IS NULL OR p.status = @status)
      ORDER BY p.id DESC", new { status });

    return Results.Ok(rows);
});

// อนุมัติคำขอ (บวกเงินเข้า wallet + ลง wallet_tx + อัปเดตสถานะ)
admin.MapPost("/topups/{id:int}/approve", async (int id, HttpContext ctx) =>
{
    var adminName = ctx.User.Identity?.Name ?? "admin";

    using var c = new SqliteConnection(cs);
    await c.OpenAsync();
    using var tx = c.BeginTransaction();

    var p = await c.QuerySingleOrDefaultAsync(
        "SELECT rider_id, amount, status FROM payments WHERE id=@id",
        new { id }, tx);

    if (p is null) return Results.NotFound(new { error = "ไม่พบรายการ" });
    if ((string)p.status != "pending") return Results.BadRequest(new { error = "สถานะต้องเป็น pending เท่านั้น" });

    await c.ExecuteAsync("UPDATE riders SET wallet = wallet + @a WHERE id=@rid",
        new { a = (double)p.amount, rid = (long)p.rider_id }, tx);

    await c.ExecuteAsync(@"INSERT INTO wallet_tx(rider_id, amount, type, note, created_at)
                           VALUES(@rid, @a, 'topup', 'เติมเครดิต (อนุมัติสลิป)', CURRENT_TIMESTAMP)",
        new { rid = (long)p.rider_id, a = (double)p.amount }, tx);

    await c.ExecuteAsync(@"UPDATE payments
                           SET status='approved', approved_at=CURRENT_TIMESTAMP, approved_by=@by
                           WHERE id=@id", new { id, by = adminName }, tx);

    tx.Commit();

    var bal = await c.ExecuteScalarAsync<double>(
        "SELECT wallet FROM riders WHERE id=@rid", new { rid = (long)p.rider_id });

    return Results.Ok(new { ok = true, balance = bal });
});

// ปฏิเสธคำขอ (ใส่เหตุผล)
admin.MapPost("/topups/{id:int}/reject", async (int id, AdminRejectDto body) =>
{
    if (string.IsNullOrWhiteSpace(body.Reason))
        return Results.BadRequest(new { error = "กรุณาระบุเหตุผล" });

    using var c = new SqliteConnection(cs);
    var rows = await c.ExecuteAsync(
        "UPDATE payments SET status='rejected', note=@r WHERE id=@id",
        new { id, r = body.Reason });

    return rows > 0 ? Results.Ok(new { ok = true }) : Results.NotFound(new { error = "ไม่พบรายการ" });
});



var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
app.Run($"http://0.0.0.0:{port}");


record RiderEditDto(string Name, string Phone, string Email, string Username, string Address, int Is_Approved);
record OrderStatusDto(string Status);
record WalletAdjustDto(int RiderId, double Amount, string? Type, string? Note);
record FeeDto(double PlatformRate, double BaseDelivery, double RainSurcharge);
record RejectDto(string Reason);
record AdminRejectDto(string Reason);



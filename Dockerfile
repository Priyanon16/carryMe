# --- build stage ---
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /out

# --- runtime stage ---
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# ติดตั้ง rclone + sqlite3
RUN apt-get update && apt-get install -y rclone sqlite3 && rm -rf /var/lib/apt/lists/*

# คัดลอกไฟล์ publish ที่ build มา
COPY --from=build /out .

# คัดลอกสคริปต์เริ่มต้น
COPY start.sh /start.sh
# แก้ไขกรณีไฟล์มาจาก Windows (CRLF) เพื่อไม่ให้ bash error
RUN sed -i 's/\r$//' /start.sh && chmod +x /start.sh

# บังคับ .NET ให้ bind ไปที่พอร์ตที่ Render กำหนด
ENV ASPNETCORE_URLS=http://0.0.0.0:${PORT}

# รันสคริปต์เริ่มต้น
CMD ["/start.sh"]

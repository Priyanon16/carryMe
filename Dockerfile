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

# สคริปต์เริ่มต้น (จะรัน rclone restore/backup + รันเว็บ)
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Render จะใส่ PORT ให้เอง → ชี้ URL ให้ .NET ฟังพอร์ตนี้
ENV ASPNETCORE_URLS=http://0.0.0.0:${PORT}

# รันสคริปต์เริ่มต้น
CMD ["/start.sh"]

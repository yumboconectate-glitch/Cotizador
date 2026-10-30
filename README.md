# 🧾 Cotizador Abierto

Sistema completo de **cotizaciones, aceptación en línea, firma electrónica, órdenes de servicio, cartera y facturación** para pequeñas empresas. Pensado para ISPs, integradores de tecnología, servitecas y cualquier negocio que cotice, firme y cobre.

**Un solo contenedor Docker. Sin base de datos externa. Sin servicios de pago.**

> Elaborado con Claude (Anthropic) 🤖 — construido y probado en producción en un ISP real de Colombia.

---

## ✨ Funcionalidades

### Cotizaciones
- Membrete profesional con tu logo, PDF generado en el navegador (jsPDF)
- **Botón "ACEPTO ESTA PROPUESTA" dentro del PDF**: el cliente hace clic y acepta en línea
- **Enlace público de descarga** para compartir por WhatsApp o correo
- Envío por **correo con el PDF adjunto** (SMTP propio)
- Catálogo con costo, % de utilidad y precio; **buscador con autocompletado** en los ítems
- Separación automática **código / descripción** (ej: `DS2CD2610FI` + texto técnico)
- **⚡ Combos de cotización rápida**: paquetes preconfigurados (ej: "Kit 4 cámaras") que se agregan con un clic; editor de combos incluido, con precios fijos o tomados del catálogo vigente
- **Edición de cotizaciones** conservando el número; IVA opcional, descuento, total en letras
- **Importador de listas de precios en Excel** (multihoja, auto-detección de columnas, % utilidad, actualización masiva de precios del proveedor)

### Aceptación en línea (estilo net2phone)
- El cliente pulsa el botón del PDF → página animada "generando tu orden de servicio"
- → "✓ Tu orden está lista para ser firmada" → **VAMOS** → firma electrónica
- Idempotente (doble clic no duplica), marca la cotización como Aceptada y **avisa por correo a la empresa** en el momento de la aceptación

### Órdenes de servicio (dos esquemas)
- **🛠 Venta e instalación de equipos**: tabla Ítem/Descripción/Cant/Vlr unitario/Vlr total + dirección de instalación
- **🌐 Servicio recurrente**: Servicio/Ancho de banda/Cargo instalación/Recurrente mensual
- Detección automática del tipo al convertir una cotización; subtotales automáticos

### Firma electrónica propia (sin servicios externos)
- Enlace único por documento, **verificación de identidad por código OTP al correo**
- Firma en canvas (móvil/tablet/PC), evidencia: hash SHA-256, IP, dispositivo, fecha
- Pantalla final de **¡Felicitaciones!** con el detalle de lo contratado y datos de contacto
- Flujo de **aprobación**: al aprobar, el cliente recibe automáticamente los documentos legales de la empresa (RUT, cámara, certificado bancario...) + enlace público de documentos

### Pagos, cartera y facturación
- **Abonos con comprobante adjunto** y correo HTML de estado de cuenta (Total/Abonado/Saldo)
- Confirmación de abono y estado de cuenta **por WhatsApp** con un clic
- Tarjeta de **cartera** con el total por cobrar
- **Webhook de facturación al CRM**: al aprobar una orden con IVA, se envía el paquete de la factura (cliente, ítems, base, IVA, total) a la URL que configures — ideal con n8n hacia Alegra, Siigo, WispHub, etc. Disparo automático + botón manual

### Seguimiento comercial
- **Estados** por cotización (enviada → negociación → aceptada → rechazada, + vencida automática)
- **Contador de vistas del PDF** 👁 y **dashboard mensual** (cotizado, aceptado, cobrado, por vendedor, top productos)

### Multiusuario, seguridad y automatización
- Roles **administrador / vendedor** aplicados en el servidor
- bcrypt, JWT httpOnly+Secure, rate limit, tokens criptográficos, escritura atómica
- Confirmación escribiendo `ELIMINAR` para cualquier borrado; blindaje anti doble-clic
- **API para automatizaciones** (n8n, bots de WhatsApp): crear cotizaciones con PDF generado en el servidor, convertir a orden con enlace de firma — autenticación por `X-Api-Key`
- Endpoint `/salud` para monitoreo (Uptime Kuma)

---

## 🚀 Instalación (5 minutos)

Requisitos: Docker y Docker Compose.

```bash
git clone https://github.com/TU_USUARIO/cotizador-abierto.git
cd cotizador-abierto
cp env.ejemplo .env
nano .env        # configura tus valores
docker compose up -d --build
```

Abre `http://tu-servidor:8087` — la primera visita te pedirá crear el usuario administrador.

### Variables de entorno (.env)

| Variable | Descripción |
|---|---|
| `JWT_SECRET` | Llave de sesiones. Genera una: `openssl rand -hex 32` |
| `PUBLIC_URL` | URL pública (para enlaces de PDF, aceptación y firma) |
| `SMTP_HOST/PORT/USER/PASS/FROM` | Tu servidor de correo (también configurable desde Ajustes) |
| `N8N_API_KEY` | Llave para la API de automatización (opcional) |

### Detrás de un proxy (Nginx Proxy Manager, Traefik...)
Publica el puerto 8087 con SSL. Las cookies usan el flag `Secure`, así que **el acceso debe ser por HTTPS** en producción.

---

## ⚙️ Primeros pasos

1. **Ajustes** → datos de tu empresa, logo, firma del representante, IVA, textos.
2. **Ajustes → SMTP** → configura el correo y usa el botón de prueba.
3. **Ajustes → Documentos de la empresa** → sube RUT, cámara, certificado bancario.
4. **Ajustes → Facturación electrónica** → URL del webhook hacia tu CRM (opcional).
5. **Productos/Servicios** → carga tu catálogo o **importa el Excel de tu proveedor**.
6. **Cotizar → ⚙ Administrar combos** → arma tus kits de venta rápida.
7. **Usuarios** → crea a tus vendedores (rol vendedor: sin acceso a Ajustes).

---

## 🔌 API para automatizaciones

```bash
# Crear cotización (PDF en el servidor, con botón de aceptación)
curl -X POST https://tu-dominio/api/n8n/cotizacion \
  -H "X-Api-Key: TU_LLAVE" -H "Content-Type: application/json" \
  -d '{"cliente":{"nombre":"Empresa X","correo":"x@y.com","tel":"3001234567"},
       "items":[{"nombre":"camara","cant":4},{"nombre":"instalacion","cant":1,"precio":150000}],
       "descuento":5}'

# Convertir en orden de servicio con enlace de firma
curl -X POST https://tu-dominio/api/n8n/orden \
  -H "X-Api-Key: TU_LLAVE" -H "Content-Type: application/json" \
  -d '{"numero":"COT-0001"}'
```

### Webhook de facturación (hacia tu CRM)
Al aprobar una orden con IVA, el sistema hace POST a tu URL con:
```json
{ "evento": "orden_aprobada",
  "cliente": { "nombre": "...", "tipoDoc": "NIT", "numDoc": "...", "correo": "...", "tel": "..." },
  "items": [ { "item": "...", "desc": "...", "cant": 4, "vlrUnitario": 250000, "vlrTotal": 1000000 } ],
  "totales": { "subtotal": 0, "base": 0, "ivaPct": 19, "iva": 0, "total": 0 } }
```
Mapéalo en n8n/Zapier hacia tu sistema de facturación (Alegra, Siigo, etc.).

---

## 🗃️ Datos y respaldo

Todo vive en el volumen Docker `cotz-data` (JSON con escritura atómica + PDFs/adjuntos):

```bash
docker run --rm -v cotizador_cotz-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/respaldo-cotizador-$(date +%F).tar.gz /data
```

Automatízalo con cron y guárdalo **fuera** del servidor.

---

## ⚖️ Nota legal sobre la firma electrónica

La firma incluida es **firma electrónica** (en Colombia: Ley 527 de 1999 y Decreto 2364 de 2012), con evidencia de identidad (OTP al correo), integridad (hash SHA-256) y trazabilidad. No es firma digital certificada por entidad acreditada. Revisa la normativa de tu país para tu caso de uso.

---

## 🤝 Contribuir

Issues y PRs bienvenidos. Este proyecto nació de la necesidad real de un ISP pequeño y se comparte para que cualquier negocio lo use y lo mejore.

**Licencia MIT** — úsalo, modifícalo, véndelo si quieres. Solo conserva el aviso de licencia.

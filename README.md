# 03-dhcp-spoofing
Ataque DHCP Spoofing

## Objetivo del Laboratorio
Demostrar cómo un atacante puede levantar un servidor DHCP falso
(Rogue DHCP) que responda antes que el servidor legítimo, asignando
a los clientes una configuración maliciosa donde el atacante actúa
como gateway y/o servidor DNS, logrando interceptar todo el tráfico
de los clientes afectados.

---

## Objetivo del Script
Levantar un servidor DHCP falso que responda a DHCP Discover y
DHCP Request con configuración maliciosa, redirigiendo el tráfico
de las víctimas a través del atacante.

### Parámetros

| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `-i` | Interfaz de red (ej: eth0) | Obligatorio |
| `--pool` | Rango de IPs (ej: 192.168.1.200-220) | Obligatorio |
| `--gateway` | Gateway a anunciar (IP del atacante) | Obligatorio |
| `--dns` | Servidor DNS a anunciar | 8.8.8.8 |
| `--subnet` | Máscara de subred | 255.255.255.0 |
| `--lease` | Tiempo de arrendamiento en segundos | 60 |

### Requisitos
- Sistema operativo: Kali Linux / Ubuntu
- Python 3.8+
- Scapy: `pip3 install scapy`
- Privilegios root

---

## Funcionamiento del Script

1. Escucha paquetes UDP en puertos 67/68 (DHCP)
2. Al recibir **DHCP Discover** responde con DHCP Offer:
   - IP del pool para el cliente
   - Gateway = IP del atacante
   - DNS = IP del atacante
   - Lease time corto para forzar renovaciones
3. Al recibir **DHCP Request** responde con DHCP ACK confirmando
4. Al recibir **DHCP Release** libera la IP del pool


## Uso

```bash
# Ataque básico
sudo python3 dhcp_spoof.py -i eth0 \
    --pool 192.168.1.200-220 \
    --gateway 192.168.1.50

# Con DNS falso y lease corto
sudo python3 dhcp_spoof.py -i eth0 \
    --pool 192.168.1.200-220 \
    --gateway 192.168.1.50 \
    --dns 192.168.1.50 \
    --lease 30

# Verificar desde la víctima que obtuvo IP del servidor falso
ip route
ip addr show
```

### Ataque combinado con DHCP Starvation
```bash
# Paso 1: Agotar pool legítimo
sudo python3 dhcp_starvation.py -i eth0 -c 300 &

# Paso 2: Levantar servidor falso
sudo python3 dhcp_spoof.py -i eth0 \
    --pool 192.168.1.200-250 \
    --gateway 192.168.1.50
```


## Contramedidas

### En el switch Cisco
```cisco
! DHCP Snooping — solo permite respuestas desde puertos confiables
ip dhcp snooping
ip dhcp snooping vlan 1,10,20
!
! Puerto del servidor DHCP legítimo = trusted
interface GigabitEthernet0/2
 ip dhcp snooping trust
!
! Puerto del router = trusted
interface GigabitEthernet0/1
 ip dhcp snooping trust
!
! Puertos de clientes = untrusted con límite de tasa
interface range FastEthernet0/1-24
 no ip dhcp snooping trust
 ip dhcp snooping limit rate 15
```

### Verificación de la contramedida
```cisco
show ip dhcp snooping
show ip dhcp snooping binding
show ip dhcp snooping statistics
```

---
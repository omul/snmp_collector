#!/usr/bin/python3 
import netsnmp
import pymssql
import configparser
import re
from ldap3 import Server,Connection,ALL
from functools import reduce


if __name__ == "__main__":
    path = "settings.ini"

    config = configparser.ConfigParser()
    config.read(path)

    hosts = [host.strip() for host in config.get("SNMP", "hosts").split(',')]

    community = config.get("SNMP", "community")
    version = config.get("SNMP", "version")
    kernel = config.get("SNMP", "kernel")

    server = config.get("Database", "server")
    base = config.get("Database", "base")
    user = config.get("Database", "user")
    password = config.get("Database", "password")

    sccm_server = config.get("SCCM", "server")
    sccm_base = config.get("SCCM", "base")
    sccm_user = config.get("SCCM", "user")
    sccm_password = config.get("SCCM", "password")
    sccm_site = config.get("SCCM", "site")

    LDAP_USER = config.get("AD", "LDAP_USER")
    LDAP_PASS = config.get("AD", "LDAP_PASS")
    LDAP_SERV = config.get("AD", "LDAP_SERV")
    LDAP_BASE = config.get("AD", "LDAP_BASE")

    #    sysName.0 = .1.3.6.1.2.1.1.5.0
    #    sysLocation.0 = .1.3.6.1.2.1.1.6.0
    #    sysContact.0 = .1.3.6.1.2.1.1.4.0
    #    sysUpTimeInstance = .1.3.6.1.2.1.1.3.0
    #    sysDescr.0 = .1.3.6.1.2.1.1.1.0

    conn = pymssql.connect(server, user, password, base)
    cursor = conn.cursor()

# Import from SCCM
    print('Import from SCCM', end='', flush=True)
    with pymssql.connect(sccm_server, sccm_user, sccm_password, sccm_base) as sccm_conn:
        with sccm_conn.cursor() as sccm_cursor:
            sccm_cursor.execute("""SELECT  User_DISC.Full_User_Name0 as UserName
                ,	v_R_System.User_Name0 as Login
                ,	v_R_System.Name0 as Name
                ,	i.IP_Addresses0 as IP
                ,	LOWER(REPLACE(MAC_Addresses0, ':', '')) as mac
                FROM [CM_RG2].[dbo].[v_R_System]
                LEFT JOIN (SELECT * FROM [CM_RG2].[dbo].[v_RA_System_IPAddresses] WHERE len([IP_Addresses0]) < 16) i on i.ResourceID=v_R_System.ResourceID 
                LEFT JOIN [CM_RG2].[dbo].[User_DISC] on User_DISC.User_Name0=v_R_System.User_Name0 
                LEFT JOIN [CM_RG2].[dbo].[v_RA_System_MACAddresses] ON v_RA_System_MACAddresses.ResourceID=v_R_System.ResourceID 
                WHERE v_R_System.AD_Site_Name0 like '%s'""" % sccm_site)
            cursor.execute('DELETE FROM [network].[dbo].[sccm]')
            conn.commit()
            cursor.executemany("""INSERT INTO [network].[dbo].[sccm] ([UserName], [login], [name], [ip], [mac]) 
                VALUES (%s, %s, %s, %s, %s) """, sccm_cursor)
            conn.commit()
    print(' done!')
# Import from LDAP
    print('Import from LDAP', end='', flush=True)
    ldap_conn = Connection(LDAP_SERV, LDAP_USER, LDAP_PASS, auto_bind=True)
    ldap_conn.search(LDAP_BASE, '(objectclass=person)',
                attributes=['sAMAccountname', 'telephoneNumber', 'department', 'title', 'physicalDeliveryOfficeName'])
    cursor.execute('DELETE FROM [network].[dbo].[ad]')
    cursor.executemany("INSERT INTO [network].[dbo].[ad] (sAMAccountname, telephoneNumber, department, title, physicalDeliveryOfficeName) VALUES (%s, %s, %s, %s, %s)",
        [((None if str(entry.sAMAccountname) == '[]' else str(entry.sAMAccountname))
            , None if str(entry.telephoneNumber) == '[]' else str(entry.telephoneNumber)
            , None if str(entry.department) == '[]' else str(entry.department)
            , None if str(entry.title) == '[]' else str(entry.title)
            , None if str(entry.physicalDeliveryOfficeName) == '[]' else str(entry.physicalDeliveryOfficeName)) for entry in ldap_conn.entries])
    conn.commit()
    print(' done!')

    print('Import from SNMP', end='', flush=True)
    for host in hosts:
        arg = {
            "Community": community,
            "DestHost": host,
            "Version": int(version),
            "UseNumeric": 1,
        }

        cursor.execute("DELETE FROM [network].[dbo].[hosts] WHERE host = %s", host)

        sysName = sysLocation = sysContact = sysUpTimeInstance = sysDescr = b''

        try:
            session = netsnmp.Session(**arg)
        except netsnmp.client.Error:
            print('Error: %s' % host)
            continue

        sysName, sysLocation, sysContact, sysUpTimeInstance, sysDescr = session.get(netsnmp.VarList(
            netsnmp.Varbind('.1.3.6.1.2.1.1.5.0'),
            netsnmp.Varbind('.1.3.6.1.2.1.1.6.0'),
            netsnmp.Varbind('.1.3.6.1.2.1.1.4.0'),
            netsnmp.Varbind('.1.3.6.1.2.1.1.3.0'),
            netsnmp.Varbind('.1.3.6.1.2.1.1.1.0')))

        if session.ErrorInd:
            print('\nError: %s %s' % (host, session.ErrorStr))
            continue

        rec = (host,
               str(sysName, 'utf-8'),
               str(sysLocation, 'utf-8'),
               str(sysContact, 'utf-8'),
               str(sysUpTimeInstance, 'utf-8'),
               str(sysDescr, 'utf-8'))

        cursor.execute("""
          INSERT INTO hosts (host, "sysName", sysLocation, sysContact, sysUpTimeInstance, sysDescr) 
          VALUES (%d, %s, %s, %s, %d, %s)
        """, rec)
    #    conn.commit()

# ARP table
        if host=='10.30.30.200':
            arps = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.3.1.1.2'))
            res = session.walk(arps)
            cursor.executemany("INSERT INTO arps (host, ip, mac) VALUES (%s, %s, %s)",
                [(host, re.search(r'([0-9]{1,3}[\.]){2}[0-9]{1,3}$', arp.tag).group(0) + '.' + arp.iid, arp.val.hex())for arp in arps])

# Ports
        ports = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.31.1.1.1.1'))
        res = session.walk(ports)
        cursor.executemany("INSERT INTO ports (host, port, name) VALUES (%s, %s, %s)",
            [(host, port.iid, str(port.val, 'utf-8')) for port in ports])

# VLANs
        if b'isco' in sysDescr:
            vlans = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.4.1.9.9.46.1.3.1.1.2'))
        else:
            vlans = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.17.7.1.4.2.1.3'))
        res = session.walk(vlans)
        cursor.executemany("INSERT INTO vlans (host, vlan) VALUES (%s, %s)",
           [(host, vlan.iid) for vlan in vlans])

# Trunks or tagged
# Cisco: vlanTrunkPortDynamicStatus 1.3.6.1.4.1.9.9.46.1.6.1.1.14
# .1.3.6.1.2.1.17.7.1.4.3.1.4
# HP:
# dot1qVlanCurrentEgressPorts 1.3.6.1.2.1.17.7.1.4.2.1.4
# dot1qVlanCurrentUntaggedPorts 1.3.6.1.2.1.17.7.1.4.2.1.5

        if b'isco' in sysDescr:
            tags = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.4.1.9.9.46.1.6.1.1.14'))
            res = session.walk(tags)
            cursor.executemany("INSERT INTO vlanTrunkPortDynamicStatus(host, port, status) VALUES (%s, %s, %s)",
                   [(host, tag.iid, str(tag.val, 'utf-8')) for tag in tags])
        else:

            res = session.walk(netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.17.7.1.4.2.1.4')))
            l = [int.from_bytes(x, byteorder='little') for x in res]
            eggress = reduce(lambda r, x: r | x, l)

            res1 = session.walk(netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.17.7.1.4.2.1.5')))
            l1 = [int.from_bytes(x, byteorder='little') for x in res1]
            untagged = reduce(lambda r, x: r | x, l1)

            tagged=eggress-untagged


# dot1dBasePortIfIndex & dot1dTpFdbPort
        if b'isco' in sysDescr:
            for vlan in vlans:
                sarg = {
                    "Community": community+'@'+vlan.iid,
                    "DestHost": host,
                    "Version": int(version),
                    "UseNumeric": 1,
                }
                se = netsnmp.Session(**sarg)

                pids=netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.17.1.4.1.2'))    # dot1dBasePortIfIndex
                res = se.walk(pids)
                if res:
                   cursor.executemany("INSERT INTO dot1dBasePortIfIndexes (host, vlan, portid, port) VALUES (%s, %s, %s, %s)",
                       [(host, vlan.iid, pid.iid, str(pid.val, 'utf-8')) for pid in pids])

                vids = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.17.4.3.1.2'))  # dot1dTpFdbPort
                res = se.walk(vids)

#                print([(host, vlan.iid,
#                    ''.join(['{:02x}'.format(int(i)) for i in re.search(r'([0-9]{1,3}[\.]){5}[0-9]{1,3}$'
#                        , vid.tag + '.' + vid.iid).group(0).split('.')])
#                    , vid.val) for vid in vids])

#                print([(host, vlan.iid, vid.tag+'.'+vid.iid, vid.val) for vid in vids])
                if res:
                   cursor.executemany("INSERT INTO dot1dTpFdbPorts (host, vlan, mac, portid) VALUES (%s, %s, %s, %s)",
                        [(host, vlan.iid,
                        ''.join(['{:02x}'.format(int(i)) for i in re.search(r'([0-9]{1,3}[\.]){5}[0-9]{1,3}$',
                            vid.tag + '.' + vid.iid).group(0).split('.')]),
                        vid.val) for vid in vids])
        else:
            pids = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.17.1.4.1.2'))
            res = session.walk(pids)
            if res:
                cursor.executemany(
                    "INSERT INTO dot1dBasePortIfIndexes (host, vlan, portid, port) VALUES (%s, %s, %s, %s)",
                    [(host, None, pid.iid, str(pid.val, 'utf-8')) for pid in pids])

            vids = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.17.4.3.1.2'))  # dot1dTpFdbPort
            res = session.walk(vids)
            if res:
                cursor.executemany("INSERT INTO dot1dTpFdbPorts (host, vlan, mac, portid) VALUES (%s, %s, %s, %s)",
                   [(host, None,
                     ''.join(['{:02x}'.format(int(i)) for i in re.search(r'([0-9]{1,3}[\.]){5}[0-9]{1,3}$',
                         vid.tag + '.' + vid.iid).group(0).split('.')]),
                     vid.val) for vid in vids])

        # dot1dTpFdbPort
        print('.', end='', flush=True)

    conn.commit()
    conn.close()
    print(' done!')

    # print(str(res, 'utf-8'))
    #        vars = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.2.1.1.1.0'))
    # for var in vars:        print (var.tag, var.iid, var.val.hex(), var.type)
    # t = time.gmtime(time.time()-2117788507/100)

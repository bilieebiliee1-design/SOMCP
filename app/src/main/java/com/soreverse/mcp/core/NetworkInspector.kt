package com.soreverse.mcp.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface

data class EndpointInfo(
    val url: String,
    val label: String,
    val publicCandidate: Boolean,
    val externallyRoutable: Boolean,
    val note: String,
)

object NetworkInspector {
    fun endpoints(context: Context, port: Int): List<EndpointInfo> {
        val out = mutableListOf<EndpointInfo>()
        out += EndpointInfo("http://127.0.0.1:$port/mcp", "本机回环", false, false, "仅本机/ADB 端口转发可用")

        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val lp: LinkProperties? = cm.getLinkProperties(cm.activeNetwork)
        val addresses = linkedSetOf<InetAddress>()
        lp?.linkAddresses?.map(LinkAddress::getAddress)?.forEach(addresses::add)
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.toList() }
            .forEach(addresses::add)

        addresses.filter { !it.isLoopbackAddress && !it.isLinkLocalAddress }.forEach { address ->
            val rawHost = address.hostAddress ?: return@forEach
            val host = if (address is Inet6Address) "[${rawHost.substringBefore('%')}]" else rawHost
            val publicCandidate = isPublicCandidate(address)
            out += EndpointInfo(
                url = "http://$host:$port/mcp",
                label = if (address is Inet6Address) "IPv6 地址" else "局域网地址",
                publicCandidate = publicCandidate,
                externallyRoutable = publicCandidate,
                note = if (publicCandidate) "地址看起来可公网路由，仍取决于运营商/防火墙/客户端网络" else "通常仅同一局域网可访问",
            )
        }
        return out.distinctBy { it.url }
    }

    private fun isPublicCandidate(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress || address.isSiteLocalAddress) return false
        if (address is Inet4Address) {
            val b = address.address.map { it.toInt() and 0xff }
            if (b[0] == 10 || b[0] == 127) return false
            if (b[0] == 172 && b[1] in 16..31) return false
            if (b[0] == 192 && b[1] == 168) return false
            if (b[0] == 100 && b[1] in 64..127) return false
            if (b[0] == 169 && b[1] == 254) return false
        }
        if (address is Inet6Address) {
            val first = address.address[0].toInt() and 0xff
            if ((first and 0xfe) == 0xfc) return false
        }
        return true
    }
}

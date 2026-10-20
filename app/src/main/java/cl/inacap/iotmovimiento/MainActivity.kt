package cl.inacap.iotmovimiento

import android.Manifest
import android.app.*
import android.os.*
import android.bluetooth.*
import android.content.*
import android.content.pm.PackageManager
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.graphics.Color
import android.graphics.Typeface
import android.view.*
import android.widget.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.text.SimpleDateFormat
import java.util.*
import java.net.ServerSocket
import java.net.Socket
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.io.PrintWriter
import kotlin.concurrent.thread

class Store(ctx: Context): SQLiteOpenHelper(ctx,"iot.db",null,1) {
 override fun onCreate(db:SQLiteDatabase) {
  db.execSQL("CREATE TABLE users(username TEXT PRIMARY KEY,salt TEXT NOT NULL,hash TEXT NOT NULL)")
  db.execSQL("CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, moment TEXT, source TEXT, message TEXT)")
 }
 override fun onUpgrade(db:SQLiteDatabase,oldVersion:Int,newVersion:Int) {}
 fun exists():Boolean { val c=readableDatabase.rawQuery("SELECT COUNT(*) FROM users",null);c.use { it.moveToFirst();return it.getInt(0)>0 } }
 private fun digest(password:String,salt:ByteArray):String { val spec=PBEKeySpec(password.toCharArray(),salt,120000,256);return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded.joinToString("") { "%02x".format(it) } }
 fun register(u:String,p:String):Boolean { if(exists()||u.length<3||p.length<8)return false;val salt=ByteArray(16);SecureRandom().nextBytes(salt);val s=salt.joinToString(""){"%02x".format(it)};val cv=android.content.ContentValues();cv.put("username",u);cv.put("salt",s);cv.put("hash",digest(p,salt));return writableDatabase.insert("users",null,cv)!=-1L }
 fun login(u:String,p:String):Boolean {val c=readableDatabase.rawQuery("SELECT salt,hash FROM users WHERE username=?",arrayOf(u));c.use {if(!it.moveToFirst())return false;val s=it.getString(0);val b=s.chunked(2).map {x->x.toInt(16).toByte()}.toByteArray();val actual=digest(p,b);return MessageDigest.isEqual(actual.toByteArray(),it.getString(1).toByteArray())} }
 fun log(source:String,message:String){val cv=android.content.ContentValues();cv.put("moment",SimpleDateFormat("yyyy-MM-dd HH:mm:ss",Locale.getDefault()).format(Date()));cv.put("source",source);cv.put("message",message.take(250));writableDatabase.insert("events",null,cv)}
 fun history():String {val c=readableDatabase.rawQuery("SELECT moment,source,message FROM events ORDER BY id DESC LIMIT 100",null);return c.use {val b=StringBuilder();while(it.moveToNext())b.append(it.getString(0)).append(" | ").append(it.getString(1)).append(" | ").append(it.getString(2)).append("\n\n");if(b.isEmpty())"Sin registros todavía" else b.toString()} }
}
class MainActivity:Activity() {
 private lateinit var db:Store;private lateinit var container:LinearLayout
 private var socket:BluetoothSocket?=null;private var output:OutputStream?=null;private var connected=false
 private val uuid=UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
 private val blue=Color.rgb(17,43,74)
 private val peerPort=38561
 @Volatile private var server:ServerSocket?=null
 @Volatile private var peerSocket:Socket?=null
 @Volatile private var peerWriter:PrintWriter?=null
 @Volatile private var peerRunning=false
 @Volatile private var peerAuthorized=false
 private var peerPin=""
 private lateinit var peerStatus:TextView
 private lateinit var peerMessages:TextView
 private val lock=Any()
 private var peerLastMessage="Sin mensajes recibidos"
 private var peerMode="Sin conexión"
 private fun updatePeerStatus(msg:String) {
   peerMode=msg
   runOnUiThread {
     if (::peerStatus.isInitialized && peerStatus.isAttachedToWindow) peerStatus.text="Estado: $msg"
   }
 }
 private fun updatePeerMessage(msg:String) {
   peerLastMessage=msg.take(250)
   runOnUiThread {
     if (::peerMessages.isInitialized && peerMessages.isAttachedToWindow) peerMessages.text="Último evento: $peerLastMessage"
   }
 }
 private fun localIpv4():String {
   return try {
     val interfaces=NetworkInterface.getNetworkInterfaces()
     while(interfaces.hasMoreElements()) {
       val ni=interfaces.nextElement()
       if (!ni.isUp || ni.isLoopback || ni.isVirtual) continue
       val addresses=ni.inetAddresses
       while(addresses.hasMoreElements()) {
         val a=addresses.nextElement()
         if(a is Inet4Address && !a.isLoopbackAddress && a.isSiteLocalAddress) return a.hostAddress ?: "No disponible"
       }
     }
     "No disponible"
   } catch (_:Exception) { "No disponible" }
 }
 private fun broadcastEvent(message:String) {
   updatePeerMessage(message)
   synchronized(lock) {if(peerAuthorized) peerWriter?.println("EVENT|"+message.replace('\n',' ').replace('\r',' ').replace('|','/').take(220))}
 }
 private fun closePeer() {
   peerRunning=false
   peerAuthorized=false
   synchronized(lock) { try {peerWriter?.close()} catch (_:Exception){};peerWriter=null }
   try {peerSocket?.close()} catch (_:Exception){}
   try {server?.close()} catch (_:Exception){}
   peerSocket=null
   server=null
   updatePeerStatus("Sin conexión")
 }
 private fun startPeerServer(pin:String) {
   closePeer()
   peerPin=pin
   peerRunning=true
   updatePeerStatus("Esperando teléfono monitor en ${localIpv4()}:$peerPort")
   thread(name="ServidorWifiIoT") {
     try {
       val ss=ServerSocket(peerPort)
       server=ss
       while(peerRunning) {
         val incoming=try {ss.accept()} catch(e:Exception) {if(!peerRunning) break else throw e}
         if(!peerRunning) {incoming.close();break}
         try {peerSocket?.close()}catch(_:Exception){}
         peerSocket=incoming
         peerAuthorized=false
         thread(name="ClienteMonitor") {
           try {
             incoming.soTimeout=15000
             val reader=BufferedReader(InputStreamReader(incoming.getInputStream()))
             val writer=PrintWriter(incoming.getOutputStream(),true)
             if(reader.readLine() != "PIN|$peerPin") {writer.println("ERROR|PIN incorrecto");return@thread}
             if(!peerRunning) return@thread
             incoming.soTimeout=0
             synchronized(lock) {peerWriter=writer;peerAuthorized=true}
             writer.println("OK|Conectado al teléfono principal")
             db.log("WiFi", "Monitor autenticado")
             updatePeerStatus("Monitor conectado")
             while(peerRunning && reader.readLine()!=null) { /* Sólo monitoreo: no aceptar órdenes remotas */ }
           } catch(_:Exception) {} finally {
             synchronized(lock) {if(peerSocket===incoming) {peerWriter=null;peerAuthorized=false}}
             try {incoming.close()}catch(_:Exception){}
             if(peerSocket===incoming) {peerSocket=null;if(peerRunning)updatePeerStatus("Esperando teléfono monitor")}
           }
         }
       }
     } catch(e:Exception) {if(peerRunning)toast("Servidor WiFi: ${e.message}")}
     finally {if(peerRunning) closePeer()}
   }
 }
 private fun connectPeer(ip:String,pin:String) {
   closePeer()
   peerRunning=true
   updatePeerStatus("Conectando a $ip...")
   thread(name="MonitorWifiIoT") {
     var conn:Socket?=null
     try {
       conn=Socket()
       conn.connect(java.net.InetSocketAddress(ip,peerPort),7000)
       peerSocket=conn
       conn.soTimeout=10000
       val reader=BufferedReader(InputStreamReader(conn.getInputStream()))
       val writer=PrintWriter(conn.getOutputStream(),true)
       writer.println("PIN|$pin")
       val hello=reader.readLine()?:throw java.io.IOException("Sin respuesta")
       if(!hello.startsWith("OK|"))throw java.io.IOException("PIN incorrecto o conexión rechazada")
       conn.soTimeout=0
       peerAuthorized=true
       updatePeerStatus("Conectado al teléfono principal")
       db.log("WiFi","Conectado a $ip")
       while(peerRunning) {
         val line=reader.readLine()?:break
         if(line.startsWith("EVENT|")) {
           val event=line.removePrefix("EVENT|")
           db.log("WiFi remoto",event)
           updatePeerMessage(event)
         }
       }
     } catch(e:Exception) {if(peerRunning) toast("WiFi: ${e.message}")}
     finally {
       try {conn?.close()}catch(_:Exception){}
       if(peerSocket===conn) peerSocket=null
       peerAuthorized=false
       peerRunning=false
       updatePeerStatus("Sin conexión")
     }
   }
 }

 override fun onCreate(savedInstanceState:Bundle?){super.onCreate(savedInstanceState);db=Store(this);home()}
 private fun screen(title:String){val scroll=ScrollView(this);container=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL;setPadding(28,36,28,28);setBackgroundColor(Color.rgb(245,248,252))};scroll.addView(container);setContentView(scroll);label(title,25,true)}
 private fun label(t:String,size:Int=16,bold:Boolean=false){container.addView(TextView(this).apply{text=t;textSize=size.toFloat();setTextColor(blue);if(bold)setTypeface(null,Typeface.BOLD);setPadding(0,10,0,12)})}
 private fun edit(hint:String,secret:Boolean=false):EditText {val e=EditText(this);e.hint=hint;if(secret)e.inputType=129;container.addView(e);return e}
 private fun button(t:String,action:()->Unit){container.addView(Button(this).apply{text=t;setOnClickListener{action()}})}
 private fun toast(t:String){runOnUiThread{Toast.makeText(this,t,Toast.LENGTH_LONG).show()}}
 private fun home(){screen("IoT Movimiento");label("Sistema de detección de movimiento IoT con Bluetooth",19,true);label("Integrantes del proyecto original: Benjamín Gabriel Rojas Aravena y Kevin Darwin Valdivia Marín");label("Aplicaciones Móviles para IoT | INACAP");button("Ingresar / Registrarse"){auth()};label("El desarrollo y la evaluación de esta aplicación son individuales.")}
 private fun auth(){screen("Acceso local seguro");label(if(db.exists())"Inicia sesión con tu usuario" else "Primer uso: crea una cuenta local");val u=edit("Usuario (mínimo 3 caracteres)");val p=edit("Contraseña (mínimo 8 caracteres)",true);button(if(db.exists())"Iniciar sesión" else "Crear usuario") {if(db.exists()){if(db.login(u.text.toString(),p.text.toString()))dashboard() else toast("Credenciales incorrectas")}else{if(db.register(u.text.toString().trim(),p.text.toString()))dashboard() else toast("Revisa usuario y contraseña")}};button("Volver"){home()}}
 private fun dashboard(){screen("Panel principal");label("Estado Bluetooth: "+if(connected)"Conectado" else "Desconectado");button("Descripción y sensor"){description()};button("Conectar Bluetooth HC-06"){connectMenu()};button("Control de Arduino"){controls()};button("Eventos registrados"){history()};button("Comunicación entre Android"){peer()};button("Cerrar sesión"){disconnect();home()}}
 private fun description(){screen("Proyecto y sensor");label("Problema: falta de avisos oportunos de movimiento en habitaciones, bodegas o talleres.");label("Sensor: PIR HC-SR501, salida digital OUT conectada a D4 de Arduino Uno. Detecta cambios de radiación infrarroja.");label("Actuadores: LED rojo en D7 y LED verde en D6. Módulo Bluetooth HC-06: TX hacia D11 y RX hacia D10 de Arduino (con adaptación de nivel para RX del HC-06).");label("Protocolo: Bluetooth Classic SPP, 9600 baudios. Comandos: 1, 0, on-rojo, off-rojo, on-verde, off-verde.");label("Alcance: conexión local, sin acceso remoto por Internet. La app registra mensajes recibidos en SQLite.");button("Volver"){dashboard()}}
 private fun checkBt():Boolean {if(Build.VERSION.SDK_INT>=31 && checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){requestPermissions(arrayOf(Manifest.permission.BLUETOOTH_CONNECT),77);toast("Autoriza Bluetooth y vuelve a pulsar Conectar");return false};return true}
 private fun connectMenu(){if(!checkBt())return;val manager=getSystemService(BLUETOOTH_SERVICE) as BluetoothManager;val adapter=manager.adapter;if(adapter==null){toast("Este equipo no tiene Bluetooth");return};if(!adapter.isEnabled){toast("Activa Bluetooth desde Ajustes y empareja el HC-06");return};val devices=adapter.bondedDevices.toList();if(devices.isEmpty()){toast("Empareja el HC-06 en Ajustes de Bluetooth");return};val names=devices.map {"${it.name ?: "Sin nombre"} (${it.address})"}.toTypedArray();AlertDialog.Builder(this).setTitle("Seleccionar dispositivo emparejado").setItems(names){_,i->connect(devices[i])}.show()}
 private fun connect(device:BluetoothDevice){toast("Conectando...");thread {try {disconnect();val s=device.createRfcommSocketToServiceRecord(uuid);s.connect();socket=s;output=s.outputStream;connected=true;db.log("Bluetooth","Conectado a ${device.name}");toast("Conectado a ${device.name}");runOnUiThread{dashboard()};thread {try {val r=BufferedReader(InputStreamReader(s.inputStream));while(connected){val line=r.readLine()?:break;db.log("Arduino",line);broadcastEvent(line);runOnUiThread{if(::live.isInitialized)live.text="Último mensaje: $line"}}}catch(_:Exception){}finally{connected=false}} }catch(e:Exception){connected=false;toast("No se pudo conectar: ${e.message}")}}}
 private lateinit var live:TextView
 private fun send(cmd:String){val o=output;if(o==null){toast("Primero conecta Bluetooth");return};thread {try{o.write((cmd+"\n").toByteArray(Charsets.UTF_8));o.flush();db.log("Comando",cmd);broadcastEvent("Comando enviado: $cmd");toast("Enviado: $cmd")}catch(e:Exception){toast("Error al enviar: ${e.message}")}}}
 private fun controls(){screen("Control remoto Arduino");live=TextView(this).apply{text="Último mensaje: consulta el historial";textSize=16f};container.addView(live);label("Los comandos requieren conexión HC-06 activa.");button("Conectar Bluetooth"){connectMenu()};button("Activar sensor (1)"){send("1")};button("Desactivar sensor (0)"){send("0")};button("Encender LED rojo"){send("on-rojo")};button("Apagar LED rojo"){send("off-rojo")};button("Encender LED verde"){send("on-verde")};button("Apagar LED verde"){send("off-verde")};button("Ver historial"){history()};button("Volver"){dashboard()}}
 private fun history(){screen("Registro local de eventos");label(db.history());button("Actualizar"){history()};button("Volver"){dashboard()}}
 private fun peer(){
   screen("Conexión WiFi entre teléfonos")
   label("Ambos teléfonos deben estar conectados a la misma red WiFi. El teléfono principal controla Arduino por Bluetooth; el monitor recibe eventos por WiFi.")
   peerStatus=TextView(this).apply {text="Estado: $peerMode";textSize=17f};container.addView(peerStatus)
   peerMessages=TextView(this).apply {text="Último evento: $peerLastMessage";textSize=16f};container.addView(peerMessages)
   label("Dirección IP de este teléfono: ${localIpv4()}")
   label("TELÉFONO 1: PRINCIPAL",18,true)
   label("Introduce un PIN de al menos 6 cifras para autorizar un teléfono monitor.")
   val serverPin=edit("PIN compartido (6 o más cifras)",true)
   button("Iniciar servidor en teléfono principal") {
     val pin=serverPin.text.toString()
     if(!pin.matches(Regex("[0-9]{6,12}")))toast("El PIN debe contener entre 6 y 12 cifras")
     else startPeerServer(pin)
   }
   label("TELÉFONO 2: MONITOR",18,true)
   val addr=edit("IP del teléfono principal, ej. 192.168.1.20")
   val clientPin=edit("Mismo PIN del teléfono principal",true)
   button("Conectarse como monitor") {
     val ip=addr.text.toString().trim()
     val pin=clientPin.text.toString()
     if(ip.isBlank() || !pin.matches(Regex("[0-9]{6,12}")))toast("Introduce IP y PIN válidos")
     else connectPeer(ip,pin)
   }
   button("Enviar evento de prueba desde principal") {
     if(server!=null && peerAuthorized){val msg="Prueba WiFi: ${SimpleDateFormat("HH:mm:ss",Locale.getDefault()).format(Date())}";db.log("Prueba WiFi",msg);broadcastEvent(msg);toast("Evento enviado")}
     else toast("Inicia el servidor y conecta el teléfono monitor")
   }
   button("Desconectar WiFi"){closePeer()}
   button("Ver historial recibido"){history()}
   button("Volver al panel"){dashboard()}
 }
 private fun disconnect(){connected=false;try{socket?.close()}catch(_:Exception){};socket=null;output=null}
 override fun onDestroy(){closePeer();disconnect();super.onDestroy()}
}

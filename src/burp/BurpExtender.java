package burp;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.TreeMap;

import javax.swing.JMenuItem;

import mjson.Json;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner
{
	private IExtensionHelpers helpers;
	private IBurpExtenderCallbacks callbacks;
	private PrintWriter stdout;

	private final static String NAME = "Copy as requests";
	private final static String SESSION_MENU_ITEM = NAME + " with session";
	private final static String[] PYTHON_ESCAPE = new String[256];
	private final static String SESSION_VAR = "session";

	static {
		for (int i = 0x00; i <= 0xFF; i++) PYTHON_ESCAPE[i] = String.format("\\x%02x", i);
		for (int i = 0x20; i < 0x80; i++) PYTHON_ESCAPE[i] = String.valueOf((char)i);
		PYTHON_ESCAPE['\n'] = "\\n";
		PYTHON_ESCAPE['\r'] = "\\r";
		PYTHON_ESCAPE['\t'] = "\\t";
		PYTHON_ESCAPE['"'] = "\\\"";
		PYTHON_ESCAPE['\\'] = "\\\\";
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
		stdout = new PrintWriter(callbacks.getStdout(), true);
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName(NAME);
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i1 = new JMenuItem(NAME);
		i1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				copyMessages(messages, false);
			}
		});
		JMenuItem i2 = new JMenuItem(SESSION_MENU_ITEM);
		i2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				copyMessages(messages, true);
			}
		});
		return Arrays.asList(i1, i2);
	}

	private enum BodyType {JSON, DATA};

	private void copyMessages(IHttpRequestResponse[] messages, boolean withSessionObject) {
		StringBuilder py = new StringBuilder("import requests");
		
		py.append("\nif platform.system() == 'Windows':\r\n"
				+ "    proxy = {\"http\": \"http://127.0.0.1:8080\",\r\n"
				+ "             \"https\": \"http://127.0.0.1:8080\"}  # for python3 https proxy also use http protocol\r\n"
				+ "else:\r\n"
				+ "    proxy = {}");
		
		py = new StringBuilder();
		String requestsMethodPrefix =null;
		if (withSessionObject) {
			requestsMethodPrefix ="\n\ntry:\n    response = requests.session().";//python缩进4个空格
		}else {
			requestsMethodPrefix ="\n\ntry:\n    response = requests.";//python缩进4个空格
		}

		int i = 0;

		for (IHttpRequestResponse message : messages) {
			IRequestInfo ri = helpers.analyzeRequest(message);
			byte[] req = message.getRequest();
			String prefix = "burp" + i++ + "_";

			py.append("\n\n").append(prefix).append("url = \"");
			py.append(escapeQuotes(ri.getUrl().toString()));
			py.append('"');

			List<String> headers = ri.getHeaders();
			headers.remove(0);
			boolean cookiesExist = processCookies(prefix, py, headers);
			py.append('\n').append(prefix).append("headers = {");
			processHeaders(py, headers);
			py.append('}');

			BodyType bodyType = processBody(prefix, py, req, ri);

			py.append(requestsMethodPrefix);
			py.append(ri.getMethod().toLowerCase());
			py.append('(').append(prefix).append("url, headers=");
			py.append(prefix).append("headers");
			if (cookiesExist) py.append(", cookies=").append(prefix).append("cookies");
			py.append(", proxies=proxy");
			py.append(", verify=False");

			if (bodyType != null) {
				String kind = bodyType.toString().toLowerCase();
				py.append(", ").append(kind).append('=').append(prefix).append(kind);
			}
			py.append(')');


			if (isJson(message)) {
				py.append("\n    body_json = response.json()");
			}else if (isHtml(message)) {
				py.append("\n    body_text = response.content.decode(\"utf-8\")");
			}else {
				py.append("\n    body_bytes = response.content #bytes");
			}

			py.append("\nexcept Exception as e:");
			py.append("\n    print(e)");//python缩进4个空格
		}

		Toolkit.getDefaultToolkit().getSystemClipboard()
		.setContents(new StringSelection(py.toString()), this);
	}

	public boolean isJson(IHttpRequestResponse message) {
		try {
			IResponseInfo resp = helpers.analyzeResponse(message.getResponse());

			String dataType = resp.getStatedMimeType();
			String dataType1 = resp.getInferredMimeType();
			stdout.println(dataType+" "+dataType1);
			if(dataType.toLowerCase().contains("json") || dataType1.toLowerCase().contains("json")) {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public boolean isHtml(IHttpRequestResponse message) {
		try {
			IResponseInfo resp = helpers.analyzeResponse(message.getResponse());
			String dataType = resp.getStatedMimeType();
			String dataType1 = resp.getInferredMimeType();
			stdout.println(dataType+" "+dataType1);
			if(dataType.toLowerCase().contains("html") || dataType1.toLowerCase().contains("html")) {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public boolean isImage(IHttpRequestResponse message) {
		try {
			IResponseInfo resp = helpers.analyzeResponse(message.getResponse());
			String dataType = resp.getStatedMimeType();
			String dataType1 = resp.getInferredMimeType();
			stdout.println(dataType+" "+dataType1);
			if(dataType.toLowerCase().contains("image") || dataType1.toLowerCase().contains("png")
					|| dataType1.toLowerCase().contains("jpeg")) {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private static boolean processCookies(String prefix, StringBuilder py,
			List<String> headers) {
		ListIterator<String> iter = headers.listIterator();
		boolean cookiesExist = false;
		while (iter.hasNext()) {
			String header = iter.next();
			if (!header.toLowerCase().startsWith("cookie:")) continue;
			iter.remove();
			for (String cookie : header.substring(8).split("; ?")) {
				if (cookiesExist) {
					py.append(", \"");
				} else {
					cookiesExist = true;
					py.append('\n').append(prefix).append("cookies = {\"");
				}
				String[] parts = cookie.split("=", 2);
				py.append(escapeQuotes(parts[0]));
				py.append("\": \"");
				py.append(escapeQuotes(parts[1]));
				py.append('"');
			}
		}
		if (cookiesExist) py.append('}');
		return cookiesExist;
	}

	private static final Collection<String> IGNORE_HEADERS = Arrays.asList("host:", "content-length:");

	private static void processHeaders(StringBuilder py, List<String> headers) {
		boolean firstHeader = true;
		header_loop:
			for (String header : headers) {
				if (headers.indexOf(header) ==0) continue;//忽略第一行，有时候如果第一行包含了分号，也会被添加进来
				String lowerCaseHeader = header.toLowerCase();
				for (String headerToIgnore : IGNORE_HEADERS) {
					if (lowerCaseHeader.startsWith(headerToIgnore)) continue header_loop;
				}
				header = escapeQuotes(header);
				int colonPos = header.indexOf(':');
				if (colonPos == -1) continue;
				if (firstHeader) {
					firstHeader = false;
					py.append('"');
				} else {
					py.append(", \"");
				}
				py.append(header, 0, colonPos);
				py.append("\": \"");
				py.append(header, colonPos + 2, header.length());
				py.append('"');
			}
	}

	private BodyType processBody(String prefix, StringBuilder py,
			byte[] req, IRequestInfo ri) {
		int bo = ri.getBodyOffset();
		if (bo >= req.length - 2) return null;
		py.append('\n').append(prefix);
		byte contentType = ri.getContentType();
		if (contentType == IRequestInfo.CONTENT_TYPE_JSON) {
			try {
				Json root = Json.read(byteSliceToString(req, bo, req.length));
				py.append("json=");
				escapeJson(root, py);
				return BodyType.JSON;
			} catch (Exception e) {
				// not valid JSON, treat it like any other kind of data
			}
		}
		py.append("data = ");
		if (contentType == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
			py.append('{');
			boolean firstKey = true;
			int keyStart = bo, keyEnd = -1;
			for (int pos = bo; pos < req.length; pos++) {
				byte b = req[pos];
				if (keyEnd == -1) {
					if (b == (byte)'=') {
						if (pos == req.length - 1) {
							if (!firstKey) py.append(", ");
							escapeUrlEncodedBytes(req, py, keyStart, pos);
							py.append(": ''");
						} else {
							keyEnd = pos;
						}
					}
				} else if (b == (byte)'&' || pos == req.length - 1) {
					if (firstKey) firstKey = false; else py.append(", ");
					escapeUrlEncodedBytes(req, py, keyStart, keyEnd);
					py.append(": ");
					escapeUrlEncodedBytes(req, py, keyEnd + 1,
							pos == req.length - 1 ? req.length : pos);
					keyEnd = -1;
					keyStart = pos + 1;
				}
			}
			py.append('}');
		} else {
			escapeBytes(req, py, bo, req.length);
		}
		return BodyType.DATA;
	}

	private static String escapeQuotes(String value) {
		return value.replace("\\", "\\\\").replace("\"", "\\\"")
				.replace("\n", "\\n").replace("\r", "\\r");
	}

	private void escapeUrlEncodedBytes(byte[] input, StringBuilder output,
			int start, int end) {
		if (end > start) {
			byte[] dec = helpers.urlDecode(Arrays.copyOfRange(input, start, end));
			escapeBytes(dec, output, 0, dec.length);
		} else {
			output.append("''");
		}
	}

	private static final String PYTHON_TRUE = "True", PYTHON_FALSE = "False", PYTHON_NULL = "None";

	private static void escapeJson(Json node, StringBuilder output) {
		if (node.isObject()) {
			String prefix = "{";
			Map<String, Json> tm = new TreeMap(String.CASE_INSENSITIVE_ORDER);
			tm.putAll(node.asJsonMap());
			for (Map.Entry<String, Json> e : tm.entrySet()) {
				output.append(prefix);
				prefix = ", ";
				escapeString(e.getKey(), output);
				output.append(": ");
				escapeJson(e.getValue(), output);
			}
			output.append('}');
		} else if (node.isArray()) {
			output.append('[');
			final Iterator<Json> iter = node.asJsonList().iterator();
			if (iter.hasNext()) {
				escapeJson(iter.next(), output);
				while (iter.hasNext()) {
					output.append(", ");
					escapeJson(iter.next(), output);
				}
			}
			output.append(']');
		} else if (node.isString()) {
			escapeString(node.asString(), output);
		} else if (node.isBoolean()) {
			output.append(node.asBoolean() ? PYTHON_TRUE : PYTHON_FALSE);
		} else if (node.isNull()) {
			output.append(PYTHON_NULL);
		} else if (node.isNumber()) {
			output.append(node.asString());
		}
	}

	private static String byteSliceToString(byte[] input, int from, int till) {
		try {
			return new String(input, from, till - from, "ISO-8859-1");
		} catch (UnsupportedEncodingException uee) {
			throw new RuntimeException("All JVMs must support ISO-8859-1");
		}
	}

	private static void escapeString(String input, StringBuilder output) {
		output.append('"');
		int length = input.length();
		for (int pos = 0; pos < length; pos++) {
			output.append(PYTHON_ESCAPE[input.charAt(pos) & 0xFF]);
		}
		output.append('"');
	}

	private static void escapeBytes(byte[] input, StringBuilder output,
			int start, int end) {
		output.append('"');
		for (int pos = start; pos < end; pos++) {
			output.append(PYTHON_ESCAPE[input[pos] & 0xFF]);
		}
		output.append('"');
	}

	@Override
	public void lostOwnership(Clipboard aClipboard, Transferable aContents) {}
}

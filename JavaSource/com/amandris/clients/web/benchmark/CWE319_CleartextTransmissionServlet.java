package com.amandris.clients.web.benchmark;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Benchmark case CWE-319. The buyer password is posted to an http:// login URL.
 */
public class CWE319_CleartextTransmissionServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String login = request.getParameter("login");
		String password = request.getParameter("password");
		URL url = new URL("http://auth.amandris.example/login");
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("POST");
		connection.setDoOutput(true);
		OutputStream body = connection.getOutputStream();
		try {
			body.write(("login=" + login + "&password=" + password).getBytes("UTF-8"));
		} finally {
			body.close();
		}
		connection.getResponseCode();
		response.setContentType("text/plain");
		response.getWriter().write("sent");
	}
}

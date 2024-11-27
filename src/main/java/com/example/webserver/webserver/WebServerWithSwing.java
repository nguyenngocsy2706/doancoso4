package com.example.webserver.webserver;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.*;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class WebServerWithSwing {
    private static HttpServer server;
    private static JTextArea logArea; // Khu vực hiển thị log các yêu cầu
    private static JButton startButton;
    private static JButton stopButton;
    private static JTextArea clientListArea; // Khu vực hiển thị danh sách client
    private static Set<String> connectedClients = ConcurrentHashMap.newKeySet(); // Quản lý danh sách client kết nối
    private static Map<String, String> sessions = new ConcurrentHashMap<>(); // Quản lý session của các client
    private static Map<String, String> userDatabase = new ConcurrentHashMap<>(); // Giả lập cơ sở dữ liệu người dùng
    private static String rootDirectory = "www"; // Thư mục gốc chứa các tệp tin
    private static int port = 8080; // Cổng mặc định
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "1234";

    // Hàm tiện ích để kết nối cơ sở dữ liệu
    private static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }

    public static void main(String[] args) {
        // Giao diện đồ họa với Swing
        JFrame frame = new JFrame("Simple Web Server");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        logArea = new JTextArea();
        logArea.setEditable(false); // Không cho phép sửa log
        JScrollPane scrollPane = new JScrollPane(logArea);

        // Khởi tạo danh sách client
        clientListArea = new JTextArea();
        clientListArea.setEditable(false);
        clientListArea.setText("Connected Clients:\n(Chưa có client nào kết nối)");
        JScrollPane clientScrollPane = new JScrollPane(clientListArea);

        JTextField portField = new JTextField("8080", 5);
        JTextField rootDirField = new JTextField("www", 20);

        JPanel configPanel = new JPanel();
        configPanel.add(new JLabel("Port:"));
        configPanel.add(portField);
        configPanel.add(new JLabel("Root Directory:"));
        configPanel.add(rootDirField);

        JPanel panel = new JPanel();
        startButton = new JButton("Start Server");
        stopButton = new JButton("Stop Server");
        stopButton.setEnabled(false);
        panel.add(startButton);
        panel.add(stopButton);

        startButton.addActionListener(e -> {
            try {
                port = Integer.parseInt(portField.getText());
                rootDirectory = rootDirField.getText();
                startServer();
            } catch (NumberFormatException ex) {
                logArea.append("Invalid port number\n");
            }
        });

        stopButton.addActionListener(e -> stopServer());

        frame.getContentPane().add(BorderLayout.CENTER, scrollPane);
        frame.getContentPane().add(BorderLayout.EAST, clientScrollPane);
        frame.getContentPane().add(BorderLayout.SOUTH, panel);
        frame.getContentPane().add(BorderLayout.NORTH, configPanel);

        frame.setVisible(true);
    }

    // Khởi động server
    private static void startServer() {
        try {
            server = HttpServer.create(new InetSocketAddress(port), 0);

            server.createContext("/", new FileServerHandler());
            server.createContext("/about", new AboutHandler());
            server.createContext("/contact", new ContactHandler());
            server.createContext("/private", new PrivateHandler());
            server.createContext("/sessions", new SessionHandler());
            server.createContext("/login", new LoginHandler());
            server.createContext("/register", new RegisterHandler());
            server.createContext("/logout", new LogoutHandler());

            server.setExecutor(null);
            server.start();

            logArea.append("Server started on port " + port + "\n");
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
        } catch (IOException e) {
            e.printStackTrace();
            logArea.append("Error starting the server: " + e.getMessage() + "\n");
        }
    }

    // Dừng server
    private static void stopServer() {
        if (server != null) {
            server.stop(0);
            logArea.append("Server stopped\n");
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
        }
    }

    private static void updateClientList() {
        if (connectedClients.isEmpty()) {
            clientListArea.setText("Connected Clients:\n(Chưa có client nào kết nối)");
        } else {
            StringBuilder clientList = new StringBuilder("Connected Clients:\n");
            for (String client : connectedClients) {
                clientList.append(client).append("\n");
            }
            clientListArea.setText(clientList.toString());
        }
    }

    static class FileServerHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String clientIP = exchange.getRemoteAddress().getAddress().getHostAddress();
            connectedClients.add(clientIP);
            updateClientList();
            String method = exchange.getRequestMethod();
            String requestURI = exchange.getRequestURI().getPath();

            if (requestURI.equals("/")) {
                requestURI = "/";
            }

            String filePath = rootDirectory + requestURI;
            logArea.append("Received a " + method + " request for: " + requestURI + "\n");

            File file = new File(filePath);
            if (!file.exists()) {
                send404(exchange);
                return;
            }

            if (file.isDirectory()) {
                sendDirectoryListing(exchange, file);
            } else {
                sendFile(exchange, file);
            }
        }

        private void sendDirectoryListing(HttpExchange exchange, File directory) throws IOException {
            StringBuilder response = new StringBuilder("<html><body><h1>Directory listing for " + directory.getName() + "</h1><ul>");
            for (File file : directory.listFiles()) {
                String fileName = file.getName();
                String fileLink = directory.getName().equals(rootDirectory) ? "/" + fileName : directory.getName() + "/" + fileName;
                response.append("<li><a href=\"").append(fileLink).append("\">").append(fileName).append("</a></li>");
            }
            response.append("</ul></body></html>");
            sendResponse(exchange, response.toString());
        }
    }

    private static void sendFile(HttpExchange exchange, File file) throws IOException {
        String mimeType = Files.probeContentType(file.toPath());
        if (mimeType == null) {
            mimeType = "application/octet-stream";
        }

        exchange.getResponseHeaders().set("Content-Type", mimeType);
        exchange.sendResponseHeaders(200, file.length());

        OutputStream os = exchange.getResponseBody();
        Files.copy(file.toPath(), os);
        os.close();
    }

    private static void send404(HttpExchange exchange) throws IOException {
        String response = "<html><body><h1>404 Not Found</h1></body></html>";
        exchange.sendResponseHeaders(404, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes(StandardCharsets.UTF_8));
        os.close();
    }

    private static void sendResponse(HttpExchange exchange, String response) throws IOException {
        exchange.sendResponseHeaders(200, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes(StandardCharsets.UTF_8));
        os.close();
    }

    static class AboutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "" +
                    "<!DOCTYPE html>\n" +
                    "<html lang=\"en\">\n" +
                    "<head>\n" +
                    "    <meta charset=\"UTF-8\">\n" +
                    "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                    "    <title>About Us</title>\n" +
                    "    <style>\n" +
                    "        /* Reset default margin and padding */\n" +
                    "        * {\n" +
                    "            margin: 0;\n" +
                    "            padding: 0;\n" +
                    "            box-sizing: border-box;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Set background color and font style for the body */\n" +
                    "        body {\n" +
                    "            font-family: Arial, sans-serif;\n" +
                    "            background-color: #f4f4f9;\n" +
                    "            color: #333;\n" +
                    "            display: flex;\n" +
                    "            flex-direction: column;\n" +
                    "            align-items: center;\n" +
                    "            padding: 20px;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style the header */\n" +
                    "        h1 {\n" +
                    "            font-size: 2.5em;\n" +
                    "            color: #4a90e2;\n" +
                    "            margin-bottom: 10px;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style the paragraph */\n" +
                    "        p {\n" +
                    "            font-size: 1.2em;\n" +
                    "            margin-bottom: 20px;\n" +
                    "            color: #555;\n" +
                    "            max-width: 600px;\n" +
                    "            text-align: center;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style the navigation bar */\n" +
                    "        nav {\n" +
                    "            background-color: #4a90e2;\n" +
                    "            padding: 10px;\n" +
                    "            border-radius: 5px;\n" +
                    "            margin-top: 20px;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style links in the navigation */\n" +
                    "        nav a {\n" +
                    "            color: white;\n" +
                    "            text-decoration: none;\n" +
                    "            padding: 10px 20px;\n" +
                    "            font-weight: bold;\n" +
                    "            border-radius: 5px;\n" +
                    "            transition: background-color 0.3s ease;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Hover effect for navigation links */\n" +
                    "        nav a:hover {\n" +
                    "            background-color: #357ab7;\n" +
                    "        }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "<h1>About Us</h1>\n" +
                    "<p>Welcome to our about page. We are committed to providing you with the best service and information. Learn more about who we are and what we do here.</p>\n" +
                    "<nav>\n" +
                    "    <a href=\"index.html\">Home</a>\n" +
                    "</nav>\n" +
                    "</body>\n" +
                    "</html>\n";
            sendResponse(exchange, response);
        }
    }

    static class ContactHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "" +
                    "<!DOCTYPE html>\n" +
                    "<html lang=\"en\">\n" +
                    "<head>\n" +
                    "    <meta charset=\"UTF-8\">\n" +
                    "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                    "    <title>Contact Us</title>\n" +
                    "    <style>\n" +
                    "        /* Reset default margin and padding */\n" +
                    "        * {\n" +
                    "            margin: 0;\n" +
                    "            padding: 0;\n" +
                    "            box-sizing: border-box;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Set basic styles for body */\n" +
                    "        body {\n" +
                    "            font-family: Arial, sans-serif;\n" +
                    "            background-color: #f4f4f9;\n" +
                    "            color: #333;\n" +
                    "            display: flex;\n" +
                    "            flex-direction: column;\n" +
                    "            align-items: center;\n" +
                    "            padding: 20px;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style the header */\n" +
                    "        h1 {\n" +
                    "            font-size: 2.5em;\n" +
                    "            color: #4a90e2;\n" +
                    "            margin-bottom: 20px;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style the form container */\n" +
                    "        form {\n" +
                    "            background-color: white;\n" +
                    "            padding: 20px;\n" +
                    "            border-radius: 8px;\n" +
                    "            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);\n" +
                    "            width: 100%;\n" +
                    "            max-width: 400px;\n" +
                    "            display: flex;\n" +
                    "            flex-direction: column;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style form labels and inputs */\n" +
                    "        label {\n" +
                    "            font-weight: bold;\n" +
                    "            margin-bottom: 5px;\n" +
                    "            color: #555;\n" +
                    "        }\n" +
                    "\n" +
                    "        input[type=\"text\"], textarea {\n" +
                    "            width: 100%;\n" +
                    "            padding: 10px;\n" +
                    "            margin-bottom: 15px;\n" +
                    "            border: 1px solid #ccc;\n" +
                    "            border-radius: 5px;\n" +
                    "            font-size: 1em;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style submit button */\n" +
                    "        input[type=\"submit\"] {\n" +
                    "            background-color: #4a90e2;\n" +
                    "            color: white;\n" +
                    "            padding: 10px;\n" +
                    "            border: none;\n" +
                    "            border-radius: 5px;\n" +
                    "            cursor: pointer;\n" +
                    "            font-size: 1em;\n" +
                    "            font-weight: bold;\n" +
                    "            transition: background-color 0.3s ease;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Hover effect for submit button */\n" +
                    "        input[type=\"submit\"]:hover {\n" +
                    "            background-color: #357ab7;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style the navigation bar */\n" +
                    "        nav {\n" +
                    "            background-color: #4a90e2;\n" +
                    "            padding: 10px;\n" +
                    "            border-radius: 5px;\n" +
                    "            margin-top: 20px;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Style links in the navigation */\n" +
                    "        nav a {\n" +
                    "            color: white;\n" +
                    "            text-decoration: none;\n" +
                    "            padding: 10px 20px;\n" +
                    "            font-weight: bold;\n" +
                    "            border-radius: 5px;\n" +
                    "            transition: background-color 0.3s ease;\n" +
                    "        }\n" +
                    "\n" +
                    "        /* Hover effect for navigation links */\n" +
                    "        nav a:hover {\n" +
                    "            background-color: #357ab7;\n" +
                    "        }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "<h1>Contact Us</h1>\n" +
                    "<form method=\"POST\" action=\"/contact\">\n" +
                    "    <label for=\"name\">Name:</label>\n" +
                    "    <input type=\"text\" id=\"name\" name=\"name\" required>\n" +
                    "\n" +
                    "    <label for=\"message\">Message:</label>\n" +
                    "    <textarea id=\"message\" name=\"message\" rows=\"4\" required></textarea>\n" +
                    "\n" +
                    "    <input type=\"submit\" value=\"Submit\">\n" +
                    "</form>\n" +
                    "<nav>\n" +
                    "    <a href=\"index.html\">Home</a>\n" +
                    "</nav>\n" +
                    "</body>\n" +
                    "</html>\n";
            sendResponse(exchange, response);
        }
    }

    static class PrivateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String sessionId = getSessionIdFromCookies(exchange);
            if (sessionId != null && sessions.containsKey(sessionId)) {
                String username = sessions.get(sessionId);
                String response = "" +
                        "<!DOCTYPE html>\n" +
                        "<html lang=\"en\">\n" +
                        "<head>\n" +
                        "    <meta charset=\"UTF-8\">\n" +
                        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                        "    <title>Private Page</title>\n" +
                        "    <style>\n" +
                        "        /* Basic styling */\n" +
                        "        body {\n" +
                        "            font-family: Arial, sans-serif;\n" +
                        "            display: flex;\n" +
                        "            flex-direction: column;\n" +
                        "            align-items: center;\n" +
                        "            padding: 20px;\n" +
                        "            background-color: #f4f4f9;\n" +
                        "            color: #333;\n" +
                        "        }\n" +
                        "\n" +
                        "        h1 {\n" +
                        "            color: #4a90e2;\n" +
                        "        }\n" +
                        "\n" +
                        "        p {\n" +
                        "            font-size: 1.2em;\n" +
                        "            color: #555;\n" +
                        "        }\n" +
                        "\n" +
                        "        /* Style for the button */\n" +
                        "        .home-button {\n" +
                        "            margin-top: 20px;\n" +
                        "            display: inline-block;\n" +
                        "            background-color: #4a90e2;\n" +
                        "            color: white;\n" +
                        "            padding: 10px 20px;\n" +
                        "            border-radius: 5px;\n" +
                        "            text-decoration: none;\n" +
                        "            font-size: 1em;\n" +
                        "            font-weight: bold;\n" +
                        "            transition: background-color 0.3s ease;\n" +
                        "        }\n" +
                        "\n" +
                        "        /* Hover effect for the button */\n" +
                        "        .home-button:hover {\n" +
                        "            background-color: #357ab7;\n" +
                        "        }\n" +
                        "    </style>\n" +
                        "</head>\n" +
                        "<body>\n" +
                        "<h1>Welcome to the Private Page</h1>\n" +
                        "<p id=\"welcome-message\">Hello, User!</p>\n" +
                        "\n" +
                        "<!-- Back to Home button -->\n" +
                        "<a href=\"index.html\" class=\"home-button\">Back to Home</a>\n" +
                        "\n" +
                        "<script>\n" +
                        "\n" +
                        "    // Display the username in the welcome message\n" +
                        "    document.getElementById(\"welcome-message\").innerText = `Hello, "+username+"!`;\n" +
                        "</script>\n" +
                        "</body>\n" +
                        "</html>\n";
                sendResponse(exchange, response);
            } else {
                String response = "<html><body><h1>Access Denied</h1><p>You must <a href=\"/login\">log in</a> to view this page.</p></body></html>";
                sendResponse(exchange, response);
            }
        }
    }

    // LoginHandler: Xử lý yêu cầu đăng nhập
    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                // Đọc dữ liệu từ form đăng nhập
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
                BufferedReader br = new BufferedReader(isr);
                String formData = br.readLine();

                // Phân tích dữ liệu từ form
                Map<String, String> parameters = parseFormData(formData);
                String username = parameters.get("username");
                String password = parameters.get("password");

                // Kiểm tra tài khoản từ cơ sở dữ liệu
                if (authenticateUser(username, password)) {
                    String sessionId = UUID.randomUUID().toString();
                    sessions.put(sessionId, username);

                    // Gửi cookie sessionId cho người dùng
                    exchange.getResponseHeaders().add("Set-Cookie", "sessionId=" + sessionId);
                    String response = "<html><body><h1>Login Successful</h1><p>Welcome, " + username + "!</p><a href=\"/private\">Go to Private Page</a></body></html>";
                    sendResponse(exchange, response);
                } else {
                    String response = "<html><body><h1>Login Failed</h1><p>Invalid username or password.</p><a href=\"/login\">Try Again</a></body></html>";
                    sendResponse(exchange, response);
                }
            } else {
                // Form đăng nhập
                String response = "<html><body><h1>Login</h1><form method=\"POST\" action=\"/login\">Username: <input type=\"text\" name=\"username\"><br>Password: <input type=\"password\" name=\"password\"><br><input type=\"submit\" value=\"Login\"></form></body></html>";
                sendResponse(exchange, response);
            }
        }

        // Hàm xác thực người dùng
        private boolean authenticateUser(String username, String password) {
            try (Connection conn = getConnection()) {
                String query = "SELECT password FROM users WHERE username = ?";
                PreparedStatement stmt = conn.prepareStatement(query);
                stmt.setString(1, username);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    String storedPassword = rs.getString("password");
                    return storedPassword.equals(password);
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
            return false;
        }
    }


    // RegisterHandler: Xử lý yêu cầu đăng ký tài khoản mới
    static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                // Đọc dữ liệu từ form đăng ký
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
                BufferedReader br = new BufferedReader(isr);
                String formData = br.readLine();

                Map<String, String> parameters = parseFormData(formData);
                String username = parameters.get("username");
                String password = parameters.get("password");

                // Thêm người dùng vào cơ sở dữ liệu
                if (registerUser(username, password)) {
                    String response = "<html><body><h1>Registration Successful</h1><p>Welcome, " + username + "!</p><a href=\"/login\">Log in</a></body></html>";
                    sendResponse(exchange, response);
                } else {
                    String response = "<html><body><h1>Registration Failed</h1><p>Username already exists.</p><a href=\"/register\">Try Again</a></body></html>";
                    sendResponse(exchange, response);
                }
            } else {
                // Form đăng ký
                String response = "<html><body><h1>Register</h1><form method=\"POST\" action=\"/register\">Username: <input type=\"text\" name=\"username\"><br>Password: <input type=\"password\" name=\"password\"><br><input type=\"submit\" value=\"Register\"></form></body></html>";
                sendResponse(exchange, response);
            }
        }

        // Hàm đăng ký người dùng
        private boolean registerUser(String username, String password) {
            try (Connection conn = getConnection()) {
                String query = "INSERT INTO users (username, password) VALUES (?, ?)";
                PreparedStatement stmt = conn.prepareStatement(query);
                stmt.setString(1, username);
                stmt.setString(2, password);
                stmt.executeUpdate();
                return true;
            } catch (SQLException e) {
                if (e.getErrorCode() == 1062) { // Error 1062 là lỗi duplicate entry trong MySQL
                    System.out.println("Username already exists");
                } else {
                    e.printStackTrace();
                }
            }
            return false;
        }
    }


    // SessionHandler: Hiển thị thông tin phiên đăng nhập của người dùng
    static class SessionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String sessionId = getSessionIdFromCookies(exchange);
            if (sessionId != null && sessions.containsKey(sessionId)) {
                String username = sessions.get(sessionId);
                String response = "<html><body><h1>Your Session</h1><p>Username: " + username + "</p><a href=\"/logout\">Logout</a></body></html>";
                sendResponse(exchange, response);
            } else {
                String response = "<html><body><h1>Session Not Found</h1><p>You are not logged in. <a href=\"/login\">Login here</a></p></body></html>";
                sendResponse(exchange, response);
            }
        }
    }

    // LogoutHandler: Xử lý yêu cầu đăng xuất và xóa session
    static class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String sessionId = getSessionIdFromCookies(exchange);
            if (sessionId != null && sessions.containsKey(sessionId)) {
                sessions.remove(sessionId);
                String response = "<html><body><h1>Logged Out</h1><p>You have successfully logged out. <a href=\"/\">Go to Home</a></p></body></html>";
                exchange.getResponseHeaders().add("Set-Cookie", "session_id=; Max-Age=0");
                sendResponse(exchange, response);
            } else {
                String response = "<html><body><h1>Error</h1><p>No active session found. <a href=\"/login\">Login here</a></p></body></html>";
                sendResponse(exchange, response);
            }
        }
    }

    // Helper methods for cookie and form data handling
    private static String getSessionIdFromCookies(HttpExchange exchange) {
        String cookies = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookies != null) {
            for (String cookie : cookies.split(";")) {
                String[] pair = cookie.trim().split("=");
                if (pair[0].equals("session_id")) {
                    return pair[1];
                }
            }
        }
        return null;
    }

    // Phương thức phân tích dữ liệu biểu mẫu gửi lên
    private static Map<String, String> parseFormData(String formData) {
        Map<String, String> dataMap = new ConcurrentHashMap<>();
        for (String pair : formData.split("&")) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                dataMap.put(key, value);
            }
        }
        return dataMap;
    }
}
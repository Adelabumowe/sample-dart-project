import 'dart:convert';
import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_router/shelf_router.dart';
import 'package:sqlite3/sqlite3.dart';

void main() async {
  final router = Router();

  // SQL Injection vulnerability
  router.get('/user/<username>', (Request request, String username) {
    final db = sqlite3.openInMemory();
    db.execute('CREATE TABLE users (username TEXT, email TEXT)');
    db.execute("INSERT INTO users VALUES ('admin', 'admin@example.com')");
    final result = db.select("SELECT * FROM users WHERE username = '$username'");
    db.dispose();

    if (result.isNotEmpty) {
      return Response.ok(jsonEncode({'username': result.first['username'], 'email': result.first['email']}), headers: {'Content-Type': 'application/json'});
    } else {
      return Response.notFound(jsonEncode({'error': 'User not found'}), headers: {'Content-Type': 'application/json'});
    }
  });

  // XSS vulnerability
  router.get('/greet', (Request request) {
    final name = request.url.queryParameters['name'] ?? 'Guest';
    return Response.ok('<h1>Hello $name</h1>', headers: {'Content-Type': 'text/html'});
  });

  // Insecure deserialization vulnerability
  router.post('/load', (Request request) async {
    final body = await request.readAsString();
    final data = jsonDecode(body);
    return Response.ok(jsonEncode(data), headers: {'Content-Type': 'application/json'});
  });

  // Hardcoded password vulnerability
  router.post('/login', (Request request) async {
    final body = await request.readAsString();
    final data = jsonDecode(body);
    final username = data['username'];
    final password = data['password'];

    if (username == 'admin' && password == 'admin123') {
      return Response.ok(jsonEncode({'message': 'Login successful'}), headers: {'Content-Type': 'application/json'});
    } else {
      return Response.forbidden(jsonEncode({'message': 'Login failed'}), headers: {'Content-Type': 'application/json'});
    }
  });

  final handler = const Pipeline().addMiddleware(logRequests()).addHandler(router);

  final server = await shelf_io.serve(handler, 'localhost', 8080);
  print('Server listening on port ${server.port}');
}

예시 시나리오: 로그인 폼이 다음과 같은 SQL 쿼리를 사용한다고 가정합니다:

SELECT * FROM users WHERE username = '사용자입력' AND password = '비밀번호입력';
공격자가 username 필드에 ' OR 1=1; --을 입력하고, password 필드에 아무 값이나 입력하면, 실제 실행되는 SQL 쿼리는 다음과 같습니다:

SELECT * FROM users WHERE username = '' OR 1=1; --' AND password = '비밀번호입력';
이 쿼리의 효과는 OR 1=1 조건이 항상 참이므로, 데이터베이스는 모든 사용자의 정보를 반환할 것입니다. 
이 경우, 애플리케이션이 첫 번째 결과를 사용한다면 공격자는 관리자 계정으로 로그인할 수 있습니다.

또한, 공격자는 여러 개의 쿼리를 함께 사용하여 데이터베이스의 데이터를 조회할 수도 있습니다. 
username 필드에 다음과 같은 입력을 할 수 있습니다.

'; DROP TABLE users; SELECT * FROM admin WHERE '1'='1
이렇게 하면 다음과 같은 SQL 쿼리가 실행됩니다:

SELECT * FROM users WHERE username = ''; DROP TABLE users; SELECT * FROM admin WHERE '1'='1';
이 쿼리는 첫 번째 쿼리 이후에 users 테이블을 삭제하고, 두 번째 쿼리로 admin 테이블의 모든 데이터를 조회합니다.

2. 여러 개의 쿼리를 사용하여 데이터를 검색하는 방법과 결과 값을 통한 데이터 유추 방법
SQL에서는 여러 개의 쿼리를 동시에 실행하거나 복잡한 조건을 사용하여 데이터를 검색할 수 있습니다. 이를 통해 특정 데이터가 존재하는지 또는 특정 조건을 만족하는 데이터가 어떤 것인지 유추할 수 있습니다.

예시 1: 여러 개의 쿼리 실행
여러 개의 쿼리를 실행하는 방법은 SQL Injection과 비슷하게 수행될 수 있습니다. 예를 들어, 다음과 같은 입력이 있을 수 있습니다:

' UNION SELECT username, password FROM admin; --
이렇게 하면 애플리케이션이 users 테이블이 아닌 admin 테이블의 username과 password를 반환하도록 할 수 있습니다.
실제 실행되는 쿼리는 다음과 같을 것입니다:

SELECT * FROM users WHERE username = ''; UNION SELECT username, password FROM admin; --
이 쿼리는 users 테이블에서 조건을 만족하는 데이터가 없더라도, admin 테이블에서 데이터를 가져와 결과로 반환하게 됩니다.

예시 2: 데이터 유추
애플리케이션이 오류 메시지나 결과 값을 통해 데이터베이스의 구조나 데이터를 유추할 수 있는 경우가 있습니다.

예를 들어, 다음과 같은 쿼리를 생각해 봅시다:


SELECT * FROM users WHERE username = 'admin' AND password = 'wrongpassword';
이 쿼리가 실패할 경우, 애플리케이션은 "잘못된 비밀번호"와 같은 메시지를 반환할 수 있습니다. 공격자는 이를 통해 admin이라는 사용자가 존재함을 유추할 수 있습니다.

또 다른 예로, 다음과 같은 입력이 있다고 가정합니다:


' AND (SELECT COUNT(*) FROM admin) > 0; --
이렇게 하면, 실제 실행되는 쿼리는 다음과 같습니다:

SELECT * FROM users WHERE username = '' AND (SELECT COUNT(*) FROM admin) > 0; --
이 쿼리는 admin 테이블에 하나 이상의 레코드가 있는지 확인할 수 있습니다. 결과에 따라 공격자는 데이터베이스의 구조나 데이터를 유추할 수 있습니다.


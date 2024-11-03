# import pymysql.cursors
# import sqlite3
# def process(payload):
#     connection  = pymysql.connect(host='localhost',user='user',password='password',
#                                   cursorclass=pymysql.cursors.DictCursor)
    
#     try:
#         with connection.cursor() as cursor:
#             cursor.execute(payload)
#             result = cursor.fetchall()
#     except Exception as e:
#         error.append("MySQL:"+str(e))
#     finally:
#         connection.close()
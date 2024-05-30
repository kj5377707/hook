#include <stdio.h>
#include <stdlib.h>

struct hookInfo {
    int data;
    struct hookInfo* next;
};

int main() {
    // 创建三个节点
    struct hookInfo* first = (struct hookInfo*)malloc(sizeof(struct hookInfo));
    struct hookInfo* second = (struct hookInfo*)malloc(sizeof(struct hookInfo));
    struct hookInfo* third = (struct hookInfo*)malloc(sizeof(struct hookInfo));

    // 初始化节点数据
    first->data = 1;
    second->data = 2;
    third->data = 3;

    // 链接节点
    first->next = second;
    second->next = third;
    third->next = NULL;

    // 设置 now 指针
    struct hookInfo* now = first;

    // 打印初始状态
    printf("Initial state:\n");
    printf("first->data: %d\n", first->data);  // 输出 1
    printf("now->data: %d\n", now->data);      // 输出 1

    // 移动 now 指针到下一个节点
    now = now->next;

    // 打印更改后的状态
    printf("After moving now to now->next:\n");
    printf("first->data: %d\n", first->data);  // 仍然输出 1
    printf("now->data: %d\n", now->data);      // 输出 2

    // 打印指针地址以验证它们是否相同
    printf("first pointer: %p\n", (void*)first);   // 打印 first 指针的地址
    printf("now pointer: %p\n", (void*)now);       // 打印 now 指针的地址

    // 释放分配的内存
    free(first);
    free(second);
    free(third);

    return 0;
}

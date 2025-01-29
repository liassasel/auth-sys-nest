import { Controller, Get, Post, Body, Param, Delete, Patch, Query, UseGuards } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { CreateTaskDto, UpdateTaskDto } from './dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { User } from '@prisma/client';
import { Role } from 'src/auth/types/role.enum';

@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TasksController {
  constructor(private tasksService: TasksService) {}

  @Post()
  createTask(@GetUser() user: User, @Body() dto: CreateTaskDto) {
    return this.tasksService.createTask(user.id, dto);
  }

  @Get()
  getTasks(
    @GetUser() user: User,
    @Query('status') status?: string,
    @Query('priority') priority?: string,
    @Query('dueDate') dueDate?: string,
  ) {
    return this.tasksService.getTasks(user.id, Role.USER, { status, priority, dueDate });
  }

  @Patch(':id')
  updateTask(
    @GetUser() user: User,
    @Param('id') taskId: string,
    @Body() dto: UpdateTaskDto,
  ) {
    return this.tasksService.updateTask(user.id, Role.USER, parseInt(taskId), dto);
  }

  @Delete(':id')
  deleteTask(@GetUser() user: User, @Param('id') taskId: string) {
    return this.tasksService.deleteTask(user.id, Role.USER, parseInt(taskId));
  }
}
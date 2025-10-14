package parser

import (
	"fmt"
	"kiro2api/logger"
	"kiro2api/utils"
	"strings"
)

// === 辅助函数 ===

// convertInputToString 将any类型的input转换为JSON字符串
func convertInputToString(input any) string {
	if input == nil {
		return "{}"
	}

	// 如果已经是字符串，直接返回
	if str, ok := input.(string); ok {
		return str
	}

	// 将对象转换为JSON字符串
	jsonBytes, err := utils.FastMarshal(input)
	if err != nil {
		logger.Warn("转换input为JSON字符串失败", logger.Err(err))
		return "{}"
	}

	return string(jsonBytes)
}

// isToolCallEvent 检查是否为工具调用事件
func isToolCallEvent(payload []byte) bool {
	payloadStr := string(payload)
	return strings.Contains(payloadStr, "\"toolUseId\":") ||
		strings.Contains(payloadStr, "\"tool_use_id\":") ||
		strings.Contains(payloadStr, "\"name\":") && strings.Contains(payloadStr, "\"input\":")
}

// isStreamingResponse 检查是否为流式响应
func isStreamingResponse(event *FullAssistantResponseEvent) bool {
	// 检查是否包含部分内容或状态为进行中
	return event != nil && (event.MessageStatus == "IN_PROGRESS" || event.Content != "")
}

// === 事件处理器实现 ===

// CompletionEventHandler 处理代码补全事件
type CompletionEventHandler struct {
	processor *CompliantMessageProcessor
}

func (h *CompletionEventHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var data map[string]any
	if err := utils.FastUnmarshal(message.Payload, &data); err != nil {
		return nil, err
	}

	content := ""
	if c, ok := data["content"].(string); ok {
		content = c
	}

	finishReason := ""
	if fr, ok := data["finish_reason"].(string); ok {
		finishReason = fr
	}

	// 处理工具调用
	var toolCalls []ToolCall
	if tcData, ok := data["tool_calls"].([]any); ok {
		for _, tc := range tcData {
			if tcMap, ok := tc.(map[string]any); ok {
				toolCall := ToolCall{}
				if id, ok := tcMap["id"].(string); ok {
					toolCall.ID = id
				}
				if tcType, ok := tcMap["type"].(string); ok {
					toolCall.Type = tcType
				}
				if function, ok := tcMap["function"].(map[string]any); ok {
					if name, ok := function["name"].(string); ok {
						toolCall.Function.Name = name
					}
					if args, ok := function["arguments"].(string); ok {
						toolCall.Function.Arguments = args
					}
				}
				toolCalls = append(toolCalls, toolCall)
			}
		}
	}

	events := []SSEEvent{
		{
			Event: "completion",
			Data: map[string]any{
				"type":          "completion",
				"content":       content,
				"finish_reason": finishReason,
				"tool_calls":    toolCalls,
				"raw_data":      data,
			},
		},
	}

	return events, nil
}

// CompletionChunkEventHandler 处理流式补全事件
type CompletionChunkEventHandler struct {
	processor *CompliantMessageProcessor
}

func (h *CompletionChunkEventHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var data map[string]any
	if err := utils.FastUnmarshal(message.Payload, &data); err != nil {
		return nil, err
	}

	content := ""
	if c, ok := data["content"].(string); ok {
		content = c
	}

	delta := ""
	if d, ok := data["delta"].(string); ok {
		delta = d
	}

	finishReason := ""
	if fr, ok := data["finish_reason"].(string); ok {
		finishReason = fr
	}

	// 累积完整内容
	h.processor.completionBuffer = append(h.processor.completionBuffer, content)

	// 使用delta作为实际的文本增量，如果没有则使用content
	textDelta := delta
	if textDelta == "" {
		textDelta = content
	}

	events := []SSEEvent{
		{
			Event: "content_block_delta",
			Data: map[string]any{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]any{
					"type": "text_delta",
					"text": textDelta,
				},
			},
		},
	}

	// 如果有完成原因，添加完成事件
	if finishReason != "" {
		events = append(events, SSEEvent{
			Event: "content_block_stop",
			Data: map[string]any{
				"type":          "content_block_stop",
				"index":         0,
				"finish_reason": finishReason,
			},
		})
	}

	return events, nil
}

// ToolCallRequestHandler 处理工具调用请求
type ToolCallRequestHandler struct {
	toolManager *ToolLifecycleManager
}

func (h *ToolCallRequestHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var data map[string]any
	if err := utils.FastUnmarshal(message.Payload, &data); err != nil {
		return nil, err
	}

	// 从标准AWS事件格式解析工具调用信息
	toolCallID, _ := data["toolCallId"].(string)
	toolName, _ := data["toolName"].(string)

	// 如果没有直接的toolCallId，尝试解析input字段
	input := map[string]any{}
	if inputData, ok := data["input"].(map[string]any); ok {
		input = inputData
	}

	// 创建标准格式的工具调用请求
	toolCall := ToolCall{
		ID:   toolCallID,
		Type: "function",
		Function: ToolCallFunction{
			Name:      toolName,
			Arguments: "{}",
		},
	}

	// 将input转换为JSON字符串
	if len(input) > 0 {
		if argsJSON, err := utils.FastMarshal(input); err == nil {
			toolCall.Function.Arguments = string(argsJSON)
		}
	}

	request := ToolCallRequest{
		ToolCalls: []ToolCall{toolCall},
	}

	logger.Debug("标准工具调用请求处理",
		logger.String("tool_id", toolCallID),
		logger.String("tool_name", toolName),
		logger.Any("input", input))

	return h.toolManager.HandleToolCallRequest(request), nil
}

// ToolCallResultHandler 处理工具调用结果
type ToolCallResultHandler struct {
	toolManager *ToolLifecycleManager
}

func (h *ToolCallResultHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var data map[string]any
	if err := utils.FastUnmarshal(message.Payload, &data); err != nil {
		return nil, err
	}

	// 从标准AWS事件格式解析工具调用结果
	toolCallID, _ := data["toolCallId"].(string)
	result, _ := data["result"].(string)
	success, _ := data["success"].(bool)

	// 如果没有结果字符串，尝试整个data作为结果
	if result == "" {
		if resultData, exists := data["result"]; exists {
			result = fmt.Sprintf("%v", resultData)
		} else {
			result = "Tool execution completed"
		}
	}

	// 创建标准格式的工具调用结果
	toolResult := ToolCallResult{
		ToolCallID: toolCallID,
		Result:     result,
	}

	if !success {
		// 如果工具执行失败，转换为错误处理
		errorInfo := ToolCallError{
			ToolCallID: toolCallID,
			Error:      result,
		}
		return h.toolManager.HandleToolCallError(errorInfo), nil
	}

	logger.Debug("标准工具调用结果处理",
		logger.String("tool_id", toolCallID),
		logger.String("result", result),
		logger.Bool("success", success))

	return h.toolManager.HandleToolCallResult(toolResult), nil
}

// ToolCallErrorHandler 处理工具调用错误
type ToolCallErrorHandler struct {
	toolManager *ToolLifecycleManager
}

func (h *ToolCallErrorHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var errorInfo ToolCallError
	if err := utils.FastUnmarshal(message.Payload, &errorInfo); err != nil {
		return nil, err
	}

	return h.toolManager.HandleToolCallError(errorInfo), nil
}

// ToolExecutionStartHandler 处理工具执行开始事件
type ToolExecutionStartHandler struct {
	toolManager *ToolLifecycleManager
}

func (h *ToolExecutionStartHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var data map[string]any
	if err := utils.FastUnmarshal(message.Payload, &data); err != nil {
		return nil, err
	}

	// 从执行开始事件中提取工具信息并创建执行记录
	toolCallID, _ := data["toolCallId"].(string)
	toolName, _ := data["toolName"].(string)
	executionID, _ := data["executionId"].(string)

	if toolCallID != "" && toolName != "" {
		// 创建工具执行记录
		toolCall := ToolCall{
			ID:   toolCallID,
			Type: "function",
			Function: ToolCallFunction{
				Name:      toolName,
				Arguments: "{}",
			},
		}

		request := ToolCallRequest{
			ToolCalls: []ToolCall{toolCall},
		}

		logger.Debug("工具执行开始，创建执行记录",
			logger.String("tool_id", toolCallID),
			logger.String("tool_name", toolName),
			logger.String("execution_id", executionID))

		// 在工具管理器中开始执行
		h.toolManager.HandleToolCallRequest(request)
	}

	return []SSEEvent{
		{
			Event: EventTypes.TOOL_EXECUTION_START,
			Data:  data,
		},
	}, nil
}

// ToolExecutionEndHandler 处理工具执行结束事件
type ToolExecutionEndHandler struct{}

func (h *ToolExecutionEndHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var data map[string]any
	if err := utils.FastUnmarshal(message.Payload, &data); err != nil {
		return nil, err
	}

	return []SSEEvent{
		{
			Event: EventTypes.TOOL_EXECUTION_END,
			Data:  data,
		},
	}, nil
}

// SessionStartHandler 处理会话开始事件
type SessionStartHandler struct {
	sessionManager *SessionManager
}

func (h *SessionStartHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var data map[string]any
	if err := utils.FastUnmarshal(message.Payload, &data); err != nil {
		return nil, err
	}

	// 尝试多种会话ID字段名
	sessionID := ""
	if sid, ok := data["sessionId"].(string); ok {
		sessionID = sid
	} else if sid, ok := data["session_id"].(string); ok {
		sessionID = sid
	}

	if sessionID != "" {
		h.sessionManager.SetSessionID(sessionID)
		// 触发实际的会话开始
		h.sessionManager.StartSession()
	}

	return []SSEEvent{
		{
			Event: EventTypes.SESSION_START,
			Data:  data,
		},
	}, nil
}

// SessionEndHandler 处理会话结束事件
type SessionEndHandler struct {
	sessionManager *SessionManager
}

func (h *SessionEndHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	var data map[string]any
	if err := utils.FastUnmarshal(message.Payload, &data); err != nil {
		return nil, err
	}

	// 实际结束会话
	endEvents := h.sessionManager.EndSession()

	// 合并事件数据
	result := []SSEEvent{
		{
			Event: EventTypes.SESSION_END,
			Data:  data,
		},
	}

	// 添加会话管理器生成的结束事件
	result = append(result, endEvents...)

	return result, nil
}

// StandardAssistantResponseEventHandler 标准assistantResponseEvent处理器
type StandardAssistantResponseEventHandler struct {
	processor *CompliantMessageProcessor
}

func (h *StandardAssistantResponseEventHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	// 首先检查是否是工具调用相关的事件
	if isToolCallEvent(message.Payload) {
		logger.Debug("检测到工具调用事件，使用聚合器处理")
		return h.handleToolCallEvent(message)
	}

	// 作为标准事件，优先尝试解析完整格式
	if fullEvent, err := parseFullAssistantResponseEvent(message.Payload); err == nil {
		// 对于流式响应，放宽验证要求
		if isStreamingResponse(fullEvent) {
			// logger.Debug("检测到流式格式assistantResponseEvent，使用宽松验证")
			return h.handleStreamingEvent(fullEvent)
		}

		// logger.Debug("检测到完整格式assistantResponseEvent，使用标准处理器")
		return h.handleFullAssistantEvent(fullEvent)
	}

	// 如果完整格式解析失败，回退到legacy格式处理
	logger.Debug("完整格式解析失败，回退到legacy格式处理")
	return h.handleLegacyFormat(message.Payload)
}

// handleToolCallEvent 处理工具调用事件
func (h *StandardAssistantResponseEventHandler) handleToolCallEvent(message *EventStreamMessage) ([]SSEEvent, error) {
	// 直接处理工具调用事件
	var evt toolUseEvent
	if err := utils.FastUnmarshal(message.Payload, &evt); err != nil {
		logger.Warn("解析工具调用事件失败", logger.Err(err))
		return []SSEEvent{}, nil
	}

	// 创建工具调用
	toolCall := ToolCall{
		ID:   evt.ToolUseId,
		Type: "function",
		Function: ToolCallFunction{
			Name:      evt.Name,
			Arguments: convertInputToString(evt.Input),
		},
	}

	request := ToolCallRequest{
		ToolCalls: []ToolCall{toolCall},
	}

	return h.processor.toolManager.HandleToolCallRequest(request), nil
}

// handleStreamingEvent 处理流式事件
func (h *StandardAssistantResponseEventHandler) handleStreamingEvent(event *FullAssistantResponseEvent) ([]SSEEvent, error) {
	// 处理流式响应事件
	var events []SSEEvent // 提取内容
	if event.Content != "" {
		events = append(events, SSEEvent{
			Event: "content_block_delta",
			Data: map[string]any{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]any{
					"type": "text_delta",
					"text": event.Content,
				},
			},
		})
	}

	return events, nil
}

// handleFullAssistantEvent 处理完整的assistant事件
func (h *StandardAssistantResponseEventHandler) handleFullAssistantEvent(event *FullAssistantResponseEvent) ([]SSEEvent, error) {
	// 处理完整的assistant响应事件
	var events []SSEEvent // 提取文本内容
	if event.Content != "" {
		events = append(events, SSEEvent{
			Event: "content_block_start",
			Data: map[string]any{
				"type":  "content_block_start",
				"index": 0,
				"content_block": map[string]any{
					"type": "text",
					"text": event.Content,
				},
			},
		})

		events = append(events, SSEEvent{
			Event: "content_block_delta",
			Data: map[string]any{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]any{
					"type": "text_delta",
					"text": event.Content,
				},
			},
		})

		events = append(events, SSEEvent{
			Event: "content_block_stop",
			Data: map[string]any{
				"type":  "content_block_stop",
				"index": 0,
			},
		})
	}

	return events, nil
}

// handleLegacyFormat 处理旧格式数据
func (h *StandardAssistantResponseEventHandler) handleLegacyFormat(payload []byte) ([]SSEEvent, error) {
	// 尝试作为简单文本处理
	payloadStr := strings.TrimSpace(string(payload))
	if payloadStr != "" && !strings.HasPrefix(payloadStr, "{") {
		// 简单文本内容
		return []SSEEvent{{
			Event: "content_block_delta",
			Data: map[string]any{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]any{
					"type": "text_delta",
					"text": payloadStr,
				},
			},
		}}, nil
	}

	// 尝试解析为JSON
	var data map[string]any
	if err := utils.FastUnmarshal(payload, &data); err != nil {
		logger.Warn("无法解析legacy格式数据", logger.Err(err))
		return []SSEEvent{}, nil
	}

	// 基本处理
	var events []SSEEvent
	if content, ok := data["content"].(string); ok && content != "" {
		events = append(events, SSEEvent{
			Event: "content_block_delta",
			Data: map[string]any{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]any{
					"type": "text_delta",
					"text": content,
				},
			},
		})
	}

	return events, nil
}

// LegacyToolUseEventHandler 处理旧格式的工具使用事件
type LegacyToolUseEventHandler struct {
	toolManager *ToolLifecycleManager
	aggregator  *SonicStreamingJSONAggregator
}

// Handle 实现EventHandler接口
func (h *LegacyToolUseEventHandler) Handle(message *EventStreamMessage) ([]SSEEvent, error) {
	return h.handleToolCallEvent(message)
}

// handleToolCallEvent 在LegacyToolUseEventHandler中处理工具调用事件
func (h *LegacyToolUseEventHandler) handleToolCallEvent(message *EventStreamMessage) ([]SSEEvent, error) {
	// logger.Debug("LegacyToolUseEventHandler处理工具调用事件",
	// 	logger.Int("payload_len", len(message.Payload)),
	// 	logger.String("event_type", message.GetEventType()),
	// 	logger.String("message_type", message.GetMessageType()))

	// 尝试解析为工具使用事件
	var evt toolUseEvent
	if err := utils.FastUnmarshal(message.Payload, &evt); err != nil {
		logger.Warn("解析工具调用事件失败",
			logger.Err(err),
			logger.String("payload", string(message.Payload)))

	}

	// logger.Debug("成功解析工具调用事件",
	// 	logger.String("toolUseId", evt.ToolUseId),
	// 	logger.String("name", evt.Name),
	// 	logger.String("input_preview", func() string {
	// 		inputStr := convertInputToString(evt.Input)
	// 		if len(inputStr) > 50 {
	// 			return inputStr[:50] + "..."
	// 		}
	// 		return inputStr
	// 	}()),
	// 	logger.Bool("stop", evt.Stop))

	// 验证必要字段
	if evt.Name == "" || evt.ToolUseId == "" {
		logger.Warn("工具调用事件缺少必要字段",
			logger.String("name", evt.Name),
			logger.String("toolUseId", evt.ToolUseId))

		// 即使缺少字段，也尝试处理，避免完全丢弃
		if evt.Name == "" && evt.ToolUseId == "" {
			return []SSEEvent{}, nil // 完全无效的事件，直接跳过
		}
	}

	// *** 关键修复：先注册工具，再使用聚合器收集流式数据片段 ***

	// 第一步：检查工具是否已经注册，如果没有则注册
	if _, exists := h.toolManager.GetActiveTools()[evt.ToolUseId]; !exists {
		logger.Debug("首次收到工具调用片段，先注册工具",
			logger.String("toolUseId", evt.ToolUseId),
			logger.String("name", evt.Name))

		// 🔥 核心修复：直接使用上游数据中的完整input参数
		inputStr := convertInputToString(evt.Input)

		// 创建初始工具调用请求（使用完整参数）
		toolCall := ToolCall{
			ID:   evt.ToolUseId,
			Type: "function",
			Function: ToolCallFunction{
				Name:      evt.Name,
				Arguments: inputStr, // 修复：使用完整的input参数
			},
		}

		request := ToolCallRequest{
			ToolCalls: []ToolCall{toolCall},
		}

		// 先注册工具到管理器
		events := h.toolManager.HandleToolCallRequest(request)

		// 如果这不是stop事件，返回注册事件，等待后续片段
		if !evt.Stop {
			return events, nil
		}
		// 如果是stop事件，继续处理聚合逻辑
	}

	// 第二步：使用聚合器处理工具调用数据
	inputStr := convertInputToString(evt.Input)
	complete, fullInput := h.aggregator.ProcessToolData(evt.ToolUseId, evt.Name, inputStr, evt.Stop, -1)

	// 🔥 核心修复：处理未完整数据时发送增量事件而不是空事件
	if !complete {
		//logger.Debug("工具调用数据未完整，发送增量事件",
		//	logger.String("toolUseId", evt.ToolUseId),
		//	logger.String("name", evt.Name),
		//	logger.String("inputFragment", inputStr),
		//	logger.Bool("stop", evt.Stop))

		// 如果有新的输入片段，检查配置后发送参数增量事件
		if inputStr != "" && inputStr != "{}" {
			// 边界情况检查：确保工具ID有效
			if evt.ToolUseId == "" {
				logger.Warn("工具调用片段缺少有效的toolUseId，跳过增量事件发送",
					logger.String("inputFragment", inputStr))
				return []SSEEvent{}, nil
			}

			// 获取工具的块索引
			toolIndex := h.toolManager.GetBlockIndex(evt.ToolUseId)
			if toolIndex >= 0 {

				// logger.Debug("发送工具参数增量事件",
				// 	logger.String("toolUseId", evt.ToolUseId),
				// 	logger.Int("blockIndex", toolIndex),
				// 	logger.String("inputFragment", func() string {
				// 		if len(inputStr) > 100 {
				// 			return inputStr[:100] + "..."
				// 		}
				// 		return inputStr
				// 	}()),
				// 	logger.Bool("incremental_enabled", true))

				return []SSEEvent{{
					Event: "content_block_delta",
					Data: map[string]any{
						"type":  "content_block_delta",
						"index": toolIndex,
						"delta": map[string]any{
							"type":         "input_json_delta",
							"partial_json": inputStr,
						},
					},
				}}, nil
			} else {
				// 工具未注册的边界情况
				logger.Warn("尝试发送增量事件但工具未注册，可能存在时序问题",
					logger.String("toolUseId", evt.ToolUseId),
					logger.String("name", evt.Name),
					logger.String("inputFragment", inputStr))

				// 尝试紧急注册工具（容错机制）
				if evt.Name != "" {
					logger.Debug("紧急注册未注册的工具",
						logger.String("toolUseId", evt.ToolUseId),
						logger.String("name", evt.Name))

					toolCall := ToolCall{
						ID:   evt.ToolUseId,
						Type: "function",
						Function: ToolCallFunction{
							Name:      evt.Name,
							Arguments: "{}",
						},
					}

					request := ToolCallRequest{ToolCalls: []ToolCall{toolCall}}
					emergencyEvents := h.toolManager.HandleToolCallRequest(request)

					// 返回紧急注册事件，下次会正常处理增量
					return emergencyEvents, nil
				}
			}
		}

		// 如果没有新的输入或无法获取索引，返回空事件（保持向后兼容）
		return []SSEEvent{}, nil
	}

	// logger.Debug("工具调用数据聚合完成",
	// 	logger.String("toolUseId", evt.ToolUseId),
	// 	logger.String("name", evt.Name),
	// 	logger.String("fullInput", func() string {
	// 		if len(fullInput) > 100 {
	// 			return fullInput[:100] + "..."
	// 		}
	// 		return fullInput
	// 	}()))

	// 第三步：验证和更新工具参数
	if fullInput != "" {
		// 现在验证聚合后的完整JSON格式
		var testArgs map[string]any
		if err := utils.FastUnmarshal([]byte(fullInput), &testArgs); err != nil {
			logger.Warn("聚合后的工具调用参数JSON格式仍然无效",
				logger.String("toolUseId", evt.ToolUseId),
				logger.String("fullInput", fullInput),
				logger.Err(err))
		} else {
			// 聚合后的JSON格式正确，更新工具参数
			h.toolManager.UpdateToolArguments(evt.ToolUseId, testArgs)
			// logger.Debug("聚合后JSON格式验证通过，已更新工具参数",
			// 	logger.String("toolUseId", evt.ToolUseId))
		}
	}

	// 第四步：如果是完成事件，处理工具调用结果
	var events []SSEEvent
	if evt.Stop {
		result := ToolCallResult{
			ToolCallID: evt.ToolUseId,
			Result:     "Tool execution completed via toolUseEvent",
		}
		resultEvents := h.toolManager.HandleToolCallResult(result)
		events = append(events, resultEvents...)

		// logger.Debug("工具调用完成事件已处理",
		// 	logger.String("toolUseId", evt.ToolUseId),
		// 	logger.Int("result_events", len(resultEvents)))
	}

	// logger.Debug("工具调用事件处理完成",
	// 	logger.String("toolUseId", evt.ToolUseId),
	// 	logger.String("name", evt.Name),
	// 	logger.Int("generated_events", len(events)),
	// 	logger.Bool("is_complete", evt.Stop))

	return events, nil
}

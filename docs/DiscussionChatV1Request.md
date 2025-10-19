# DiscussionChatV1Request

Request for POST /1/object/discussion/chat

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiDiscussionID** | **number** | The unique ID of the Discussion | [optional] [default to undefined]
**eDiscussionRobot** | [**FieldEDiscussionRobot**](FieldEDiscussionRobot.md) |  | [default to undefined]
**tDiscussionMessage** | **string** | The Message of the Discussion | [default to undefined]

## Example

```typescript
import { DiscussionChatV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DiscussionChatV1Request = {
    fkiDiscussionID,
    eDiscussionRobot,
    tDiscussionMessage,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

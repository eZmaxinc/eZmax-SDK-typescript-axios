# NotificationtestGetElementsV1ResponseMPayload

Payload for GET /1/object/notificationtest/{pkiNotificationtestID}/getElements

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiNotificationtestID** | **number** | The unique ID of the Notificationtest | [default to undefined]
**sNotificationtestFunction** | **string** | The function name of the Notificationtest | [default to undefined]
**a_sVariableobjectProperty** | **Array&lt;string&gt;** |  | [default to undefined]
**a_objVariableobject** | **Array&lt;{ [key: string]: any; }&gt;** |  | [default to undefined]

## Example

```typescript
import { NotificationtestGetElementsV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: NotificationtestGetElementsV1ResponseMPayload = {
    pkiNotificationtestID,
    sNotificationtestFunction,
    a_sVariableobjectProperty,
    a_objVariableobject,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

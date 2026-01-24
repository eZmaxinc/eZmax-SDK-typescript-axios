# CustomNotificationsubsectiongetnotificationtestsResponse

A Notificationsubsection Object in the context of getNotificationtests

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiNotificationsubsectionID** | **number** | The unique ID of the Notificationsubsection | [default to undefined]
**fkiNotificationsectionID** | **number** | The unique ID of the Notificationsection | [default to undefined]
**objNotificationsubsectionName** | [**MultilingualNotificationsubsectionName**](MultilingualNotificationsubsectionName.md) |  | [optional] [default to undefined]
**sNotificationsectionNameX** | **string** | The name of the Notificationsection in the language of the requester | [optional] [default to undefined]
**sNotificationsubsectionNameX** | **string** | The name of the Notificationsubsection in the language of the requester | [default to undefined]
**a_objNotificationtest** | [**Array&lt;CustomNotificationtestgetnotificationtestsResponse&gt;**](CustomNotificationtestgetnotificationtestsResponse.md) |  | [default to undefined]

## Example

```typescript
import { CustomNotificationsubsectiongetnotificationtestsResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomNotificationsubsectiongetnotificationtestsResponse = {
    pkiNotificationsubsectionID,
    fkiNotificationsectionID,
    objNotificationsubsectionName,
    sNotificationsectionNameX,
    sNotificationsubsectionNameX,
    a_objNotificationtest,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

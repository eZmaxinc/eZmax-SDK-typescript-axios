# AttachmentPrivacyV1Request

Request for POST /1/object/attachment/{pkiAttachmentID}/privacy

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eAttachmentPrivacy** | [**FieldEAttachmentPrivacy**](FieldEAttachmentPrivacy.md) |  | [default to undefined]
**fkiUserIDSpecific** | **number** | The unique ID of the User | [optional] [default to undefined]

## Example

```typescript
import { AttachmentPrivacyV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttachmentPrivacyV1Request = {
    eAttachmentPrivacy,
    fkiUserIDSpecific,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

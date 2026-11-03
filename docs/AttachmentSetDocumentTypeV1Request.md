# AttachmentSetDocumentTypeV1Request

Request for POST /1/object/attachment/{pkiAttachmentID}/setDocumentType

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiDocumenttypechecklistID** | **number** | The unique ID of the Documenttypechecklist or null | [default to undefined]

## Example

```typescript
import { AttachmentSetDocumentTypeV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttachmentSetDocumentTypeV1Request = {
    fkiDocumenttypechecklistID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

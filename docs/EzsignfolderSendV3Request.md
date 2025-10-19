# EzsignfolderSendV3Request

Request for POST /3/object/ezsignfolder/{pkiEzsignfolderID}/send

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**tEzsignfolderMessage** | **string** | A custom text message that will be added to the email sent. | [optional] [default to undefined]
**eEzsignfolderMessageorder** | [**FieldEEzsignfolderMessageorder**](FieldEEzsignfolderMessageorder.md) |  | [optional] [default to undefined]
**dtEzsignfolderDelayedsenddate** | **string** | The date and time at which the Ezsignfolder will be sent in the future. | [optional] [default to undefined]
**a_fkiEzsignfoldersignerassociationID** | **Array&lt;number&gt;** |  | [default to undefined]

## Example

```typescript
import { EzsignfolderSendV3Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfolderSendV3Request = {
    tEzsignfolderMessage,
    eEzsignfolderMessageorder,
    dtEzsignfolderDelayedsenddate,
    a_fkiEzsignfoldersignerassociationID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# EzsignfolderDuplicateV1Request



## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sEzsignfolderDescription** | **string** | The description of the Ezsignfolder | [default to undefined]
**a_fkiEzsignfoldersignerassociationID** | **Array&lt;number&gt;** |  | [default to undefined]
**a_objEzsigndocument** | [**Array&lt;CustomEzsigndocumentDuplicateRequest&gt;**](CustomEzsigndocumentDuplicateRequest.md) |  | [default to undefined]
**tEzsignfolderNote** | **string** | Note about the Ezsignfolder | [optional] [default to undefined]
**bKeepenteredvalues** | **boolean** | Whether we keep the entered values or not in the Ezsignform | [optional] [default to true]

## Example

```typescript
import { EzsignfolderDuplicateV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfolderDuplicateV1Request = {
    sEzsignfolderDescription,
    a_fkiEzsignfoldersignerassociationID,
    a_objEzsigndocument,
    tEzsignfolderNote,
    bKeepenteredvalues,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

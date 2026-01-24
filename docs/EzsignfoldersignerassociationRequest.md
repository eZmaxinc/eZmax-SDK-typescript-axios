# EzsignfoldersignerassociationRequest

An Ezsignfoldersignerassociation Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiEzsignsignergroupID** | **number** | The unique ID of the Ezsignsignergroup | [optional] [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**bEzsignfoldersignerassociationReceivecopy** | **boolean** | If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\&#39;t required to sign the document. | [optional] [default to undefined]
**tEzsignfoldersignerassociationMessage** | **string** | A custom text message that will be added to the email sent. | [optional] [default to undefined]

## Example

```typescript
import { EzsignfoldersignerassociationRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfoldersignerassociationRequest = {
    pkiEzsignfoldersignerassociationID,
    fkiUserID,
    fkiEzsignsignergroupID,
    fkiEzsignfolderID,
    bEzsignfoldersignerassociationReceivecopy,
    tEzsignfoldersignerassociationMessage,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

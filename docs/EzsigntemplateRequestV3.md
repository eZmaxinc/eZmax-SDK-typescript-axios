# EzsigntemplateRequestV3

A Ezsigntemplate Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [optional] [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**sEzsigntemplateDescription** | **string** | The description of the Ezsigntemplate | [default to undefined]
**sEzsigntemplateExternaldescription** | **string** | The external description of the Ezsigntemplate | [optional] [default to undefined]
**tEzsigntemplateComment** | **string** | The comment of the Ezsigntemplate | [optional] [default to undefined]
**eEzsigntemplateRecognition** | [**FieldEEzsigntemplateRecognition**](FieldEEzsigntemplateRecognition.md) |  | [optional] [default to undefined]
**sEzsigntemplateFilenameregexp** | **string** | The filename regexp of the Ezsigntemplate. | [optional] [default to undefined]
**bEzsigntemplateAdminonly** | **boolean** | Whether the Ezsigntemplate can be accessed by admin users only (eUserType&#x3D;Normal) | [default to undefined]
**eEzsigntemplateType** | [**FieldEEzsigntemplateType**](FieldEEzsigntemplateType.md) |  | [default to undefined]

## Example

```typescript
import { EzsigntemplateRequestV3 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplateRequestV3 = {
    pkiEzsigntemplateID,
    fkiEzsignfoldertypeID,
    fkiLanguageID,
    fkiEzdoctemplatedocumentID,
    sEzsigntemplateDescription,
    sEzsigntemplateExternaldescription,
    tEzsigntemplateComment,
    eEzsigntemplateRecognition,
    sEzsigntemplateFilenameregexp,
    bEzsigntemplateAdminonly,
    eEzsigntemplateType,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

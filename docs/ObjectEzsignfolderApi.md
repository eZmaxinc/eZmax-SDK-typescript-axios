# ObjectEzsignfolderApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignfolderArchiveV1**](#ezsignfolderarchivev1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/archive | Archive the Ezsignfolder|
|[**ezsignfolderBatchDownloadV1**](#ezsignfolderbatchdownloadv1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/batchDownload | Download multiples files from an Ezsignfolder|
|[**ezsignfolderCreateObjectV1**](#ezsignfoldercreateobjectv1) | **POST** /1/object/ezsignfolder | Create a new Ezsignfolder|
|[**ezsignfolderCreateObjectV2**](#ezsignfoldercreateobjectv2) | **POST** /2/object/ezsignfolder | Create a new Ezsignfolder|
|[**ezsignfolderCreateObjectV3**](#ezsignfoldercreateobjectv3) | **POST** /3/object/ezsignfolder | Create a new Ezsignfolder|
|[**ezsignfolderDeleteObjectV1**](#ezsignfolderdeleteobjectv1) | **DELETE** /1/object/ezsignfolder/{pkiEzsignfolderID} | Delete an existing Ezsignfolder|
|[**ezsignfolderDisposeEzsignfoldersV1**](#ezsignfolderdisposeezsignfoldersv1) | **POST** /1/object/ezsignfolder/disposeEzsignfolders | Dispose Ezsignfolders|
|[**ezsignfolderDisposeV1**](#ezsignfolderdisposev1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/dispose | Dispose the Ezsignfolder|
|[**ezsignfolderDuplicateV1**](#ezsignfolderduplicatev1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/duplicate | Duplicate the Ezsignfolder|
|[**ezsignfolderEditObjectV3**](#ezsignfoldereditobjectv3) | **PUT** /3/object/ezsignfolder/{pkiEzsignfolderID} | Edit an existing Ezsignfolder|
|[**ezsignfolderEndPrematurelyV1**](#ezsignfolderendprematurelyv1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/endPrematurely | End prematurely|
|[**ezsignfolderGetActionableElementsForSignerV1**](#ezsignfoldergetactionableelementsforsignerv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getActionableElementsForSigner | Retrieve actionable elements of a user for the Ezsignfolder|
|[**ezsignfolderGetActionableElementsV1**](#ezsignfoldergetactionableelementsv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getActionableElements | Retrieve actionable elements for the Ezsignfolder|
|[**ezsignfolderGetActionableElementsV2**](#ezsignfoldergetactionableelementsv2) | **GET** /2/object/ezsignfolder/{pkiEzsignfolderID}/getActionableElements | Retrieve actionable elements for the Ezsignfolder|
|[**ezsignfolderGetActionableElementsV3**](#ezsignfoldergetactionableelementsv3) | **GET** /3/object/ezsignfolder/{pkiEzsignfolderID}/getActionableElements | Retrieve actionable elements for the Ezsignfolder|
|[**ezsignfolderGetAttachmentCountV1**](#ezsignfoldergetattachmentcountv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getAttachmentCount | Retrieve Attachment count|
|[**ezsignfolderGetAttachmentsV1**](#ezsignfoldergetattachmentsv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getAttachments | Retrieve Ezsignfolder\&#39;s Attachments|
|[**ezsignfolderGetCommunicationCountV1**](#ezsignfoldergetcommunicationcountv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationCount | Retrieve Communication count|
|[**ezsignfolderGetCommunicationListV1**](#ezsignfoldergetcommunicationlistv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationList | Retrieve Communication list|
|[**ezsignfolderGetCommunicationrecipientsV1**](#ezsignfoldergetcommunicationrecipientsv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationrecipients | Retrieve Ezsignfolder\&#39;s Communicationrecipient|
|[**ezsignfolderGetCommunicationsendersV1**](#ezsignfoldergetcommunicationsendersv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationsenders | Retrieve Ezsignfolder\&#39;s Communicationsender|
|[**ezsignfolderGetEzsignannotationsV1**](#ezsignfoldergetezsignannotationsv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getEzsignannotations | Retrieve an existing Ezsignfolder\&#39;s Ezsignannotations|
|[**ezsignfolderGetEzsigndocumentsV1**](#ezsignfoldergetezsigndocumentsv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getEzsigndocuments | Retrieve an existing Ezsignfolder\&#39;s Ezsigndocuments|
|[**ezsignfolderGetEzsigndocumentsV2**](#ezsignfoldergetezsigndocumentsv2) | **GET** /2/object/ezsignfolder/{pkiEzsignfolderID}/getEzsigndocuments | Retrieve an existing Ezsignfolder\&#39;s Ezsigndocuments|
|[**ezsignfolderGetEzsignfoldersignerassociationsV1**](#ezsignfoldergetezsignfoldersignerassociationsv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getEzsignfoldersignerassociations | Retrieve an existing Ezsignfolder\&#39;s Ezsignfoldersignerassociations|
|[**ezsignfolderGetEzsignformfieldgroupsV1**](#ezsignfoldergetezsignformfieldgroupsv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getEzsignformfieldgroups | Retrieve an existing Ezsignfolder\&#39;s Ezsignformfieldgroups|
|[**ezsignfolderGetEzsignsignaturesAutomaticV1**](#ezsignfoldergetezsignsignaturesautomaticv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getEzsignsignaturesAutomatic | Retrieve an existing Ezsignfolder\&#39;s automatic Ezsignsignatures|
|[**ezsignfolderGetEzsignsignaturesV1**](#ezsignfoldergetezsignsignaturesv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getEzsignsignatures | Retrieve an existing Ezsignfolder\&#39;s Ezsignsignatures|
|[**ezsignfolderGetFormsDataV1**](#ezsignfoldergetformsdatav1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID}/getFormsData | Retrieve an existing Ezsignfolder\&#39;s forms data|
|[**ezsignfolderGetListV1**](#ezsignfoldergetlistv1) | **GET** /1/object/ezsignfolder/getList | Retrieve Ezsignfolder list|
|[**ezsignfolderGetObjectV1**](#ezsignfoldergetobjectv1) | **GET** /1/object/ezsignfolder/{pkiEzsignfolderID} | Retrieve an existing Ezsignfolder|
|[**ezsignfolderGetObjectV2**](#ezsignfoldergetobjectv2) | **GET** /2/object/ezsignfolder/{pkiEzsignfolderID} | Retrieve an existing Ezsignfolder|
|[**ezsignfolderGetObjectV3**](#ezsignfoldergetobjectv3) | **GET** /3/object/ezsignfolder/{pkiEzsignfolderID} | Retrieve an existing Ezsignfolder|
|[**ezsignfolderImportEzsignfoldersignerassociationsV1**](#ezsignfolderimportezsignfoldersignerassociationsv1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsignfoldersignerassociations | Import an existing Ezsignfoldersignerassociation into this Ezsignfolder|
|[**ezsignfolderImportEzsigntemplatepackageV1**](#ezsignfolderimportezsigntemplatepackagev1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage | Import an Ezsigntemplatepackage in the Ezsignfolder|
|[**ezsignfolderImportEzsigntemplatepackageV2**](#ezsignfolderimportezsigntemplatepackagev2) | **POST** /2/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage | Import an Ezsigntemplatepackage in the Ezsignfolder|
|[**ezsignfolderImportEzsigntemplatepackageV3**](#ezsignfolderimportezsigntemplatepackagev3) | **POST** /3/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage | Import an Ezsigntemplatepackage in the Ezsignfolder|
|[**ezsignfolderReorderV2**](#ezsignfolderreorderv2) | **POST** /2/object/ezsignfolder/{pkiEzsignfolderID}/reorder | Reorder Ezsigndocuments in the Ezsignfolder|
|[**ezsignfolderSendV1**](#ezsignfoldersendv1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/send | Send the Ezsignfolder to the signatories for signature|
|[**ezsignfolderSendV3**](#ezsignfoldersendv3) | **POST** /3/object/ezsignfolder/{pkiEzsignfolderID}/send | Send the Ezsignfolder to the signatories for signature|
|[**ezsignfolderUnsendV1**](#ezsignfolderunsendv1) | **POST** /1/object/ezsignfolder/{pkiEzsignfolderID}/unsend | Unsend the Ezsignfolder|

# **ezsignfolderArchiveV1**
> EzsignfolderArchiveV1Response ezsignfolderArchiveV1(body)



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsignfolderArchiveV1(
    pkiEzsignfolderID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderArchiveV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderBatchDownloadV1**
> File ezsignfolderBatchDownloadV1(ezsignfolderBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderBatchDownloadV1Request: EzsignfolderBatchDownloadV1Request; //

const { status, data } = await apiInstance.ezsignfolderBatchDownloadV1(
    pkiEzsignfolderID,
    ezsignfolderBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderBatchDownloadV1Request** | **EzsignfolderBatchDownloadV1Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**File**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/zip, application/pdf, application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderCreateObjectV1**
> EzsignfolderCreateObjectV1Response ezsignfolderCreateObjectV1(ezsignfolderCreateObjectV1Request)

The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let ezsignfolderCreateObjectV1Request: Array<EzsignfolderCreateObjectV1Request>; //

const { status, data } = await apiInstance.ezsignfolderCreateObjectV1(
    ezsignfolderCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderCreateObjectV1Request** | **Array<EzsignfolderCreateObjectV1Request>**|  | |


### Return type

**EzsignfolderCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderCreateObjectV2**
> EzsignfolderCreateObjectV2Response ezsignfolderCreateObjectV2(ezsignfolderCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let ezsignfolderCreateObjectV2Request: EzsignfolderCreateObjectV2Request; //

const { status, data } = await apiInstance.ezsignfolderCreateObjectV2(
    ezsignfolderCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderCreateObjectV2Request** | **EzsignfolderCreateObjectV2Request**|  | |


### Return type

**EzsignfolderCreateObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderCreateObjectV3**
> EzsignfolderCreateObjectV3Response ezsignfolderCreateObjectV3(ezsignfolderCreateObjectV3Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderCreateObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let ezsignfolderCreateObjectV3Request: EzsignfolderCreateObjectV3Request; //

const { status, data } = await apiInstance.ezsignfolderCreateObjectV3(
    ezsignfolderCreateObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderCreateObjectV3Request** | **EzsignfolderCreateObjectV3Request**|  | |


### Return type

**EzsignfolderCreateObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderDeleteObjectV1**
> EzsignfolderDeleteObjectV1Response ezsignfolderDeleteObjectV1()


### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderDeleteObjectV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderDisposeEzsignfoldersV1**
> EzsignfolderDisposeEzsignfoldersV1Response ezsignfolderDisposeEzsignfoldersV1(ezsignfolderDisposeEzsignfoldersV1Request)



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderDisposeEzsignfoldersV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let ezsignfolderDisposeEzsignfoldersV1Request: EzsignfolderDisposeEzsignfoldersV1Request; //

const { status, data } = await apiInstance.ezsignfolderDisposeEzsignfoldersV1(
    ezsignfolderDisposeEzsignfoldersV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderDisposeEzsignfoldersV1Request** | **EzsignfolderDisposeEzsignfoldersV1Request**|  | |


### Return type

**EzsignfolderDisposeEzsignfoldersV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderDisposeV1**
> EzsignfolderDisposeV1Response ezsignfolderDisposeV1(body)



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsignfolderDisposeV1(
    pkiEzsignfolderID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderDisposeV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderDuplicateV1**
> EzsignfolderDuplicateV1Response ezsignfolderDuplicateV1(ezsignfolderDuplicateV1Request)



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderDuplicateV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderDuplicateV1Request: EzsignfolderDuplicateV1Request; //

const { status, data } = await apiInstance.ezsignfolderDuplicateV1(
    pkiEzsignfolderID,
    ezsignfolderDuplicateV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderDuplicateV1Request** | **EzsignfolderDuplicateV1Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderDuplicateV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderEditObjectV3**
> EzsignfolderEditObjectV3Response ezsignfolderEditObjectV3(ezsignfolderEditObjectV3Request)



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderEditObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderEditObjectV3Request: EzsignfolderEditObjectV3Request; //

const { status, data } = await apiInstance.ezsignfolderEditObjectV3(
    pkiEzsignfolderID,
    ezsignfolderEditObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderEditObjectV3Request** | **EzsignfolderEditObjectV3Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderEditObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderEndPrematurelyV1**
> EzsignfolderEndPrematurelyV1Response ezsignfolderEndPrematurelyV1(body)

End prematurely all Ezsigndocument of Ezsignfolder when some signatures are still required

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsignfolderEndPrematurelyV1(
    pkiEzsignfolderID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderEndPrematurelyV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetActionableElementsForSignerV1**
> EzsignfolderGetActionableElementsForSignerV1Response ezsignfolderGetActionableElementsForSignerV1()

Return the Ezsignsignatures that can be signed and Ezsignformfieldgroups that can be filled by an user at the current step in the process

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let eSignerType: 'Ezsignsigner' | 'User'; // (default to undefined)
let fkiEzsignsignerID: number; // (optional) (default to undefined)
let fkiUserID: number; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetActionableElementsForSignerV1(
    pkiEzsignfolderID,
    eSignerType,
    fkiEzsignsignerID,
    fkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|
| **eSignerType** | [**&#39;Ezsignsigner&#39; | &#39;User&#39;**]**Array<&#39;Ezsignsigner&#39; &#124; &#39;User&#39;>** |  | defaults to undefined|
| **fkiEzsignsignerID** | [**number**] |  | (optional) defaults to undefined|
| **fkiUserID** | [**number**] |  | (optional) defaults to undefined|


### Return type

**EzsignfolderGetActionableElementsForSignerV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetActionableElementsV1**
> EzsignfolderGetActionableElementsV1Response ezsignfolderGetActionableElementsV1()

Return the Ezsignsignatures that can be signed and Ezsignformfieldgroups that can be filled by the current user at the current step in the process.    Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetActionableElementsV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetActionableElementsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetActionableElementsV2**
> EzsignfolderGetActionableElementsV2Response ezsignfolderGetActionableElementsV2()

Return the Ezsignsignatures that can be signed and Ezsignformfieldgroups that can be filled by the current user at the current step in the process

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetActionableElementsV2(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetActionableElementsV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetActionableElementsV3**
> EzsignfolderGetActionableElementsV3Response ezsignfolderGetActionableElementsV3()

Return the Ezsignsignatures that can be signed and Ezsignformfieldgroups that can be filled by the current user at the current step in the process

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetActionableElementsV3(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetActionableElementsV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetAttachmentCountV1**
> EzsignfolderGetAttachmentCountV1Response ezsignfolderGetAttachmentCountV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetAttachmentCountV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetAttachmentCountV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetAttachmentsV1**
> EzsignfolderGetAttachmentsV1Response ezsignfolderGetAttachmentsV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetAttachmentsV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetAttachmentsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetCommunicationCountV1**
> EzsignfolderGetCommunicationCountV1Response ezsignfolderGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetCommunicationCountV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetCommunicationCountV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetCommunicationListV1**
> EzsignfolderGetCommunicationListV1Response ezsignfolderGetCommunicationListV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetCommunicationListV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetCommunicationListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetCommunicationrecipientsV1**
> EzsignfolderGetCommunicationrecipientsV1Response ezsignfolderGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetCommunicationrecipientsV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetCommunicationrecipientsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetCommunicationsendersV1**
> EzsignfolderGetCommunicationsendersV1Response ezsignfolderGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetCommunicationsendersV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetCommunicationsendersV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetEzsignannotationsV1**
> EzsignfolderGetEzsignannotationsV1Response ezsignfolderGetEzsignannotationsV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetEzsignannotationsV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetEzsignannotationsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetEzsigndocumentsV1**
> EzsignfolderGetEzsigndocumentsV1Response ezsignfolderGetEzsigndocumentsV1()

Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetEzsigndocumentsV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetEzsigndocumentsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetEzsigndocumentsV2**
> EzsignfolderGetEzsigndocumentsV2Response ezsignfolderGetEzsigndocumentsV2()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetEzsigndocumentsV2(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetEzsigndocumentsV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetEzsignfoldersignerassociationsV1**
> EzsignfolderGetEzsignfoldersignerassociationsV1Response ezsignfolderGetEzsignfoldersignerassociationsV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetEzsignfoldersignerassociationsV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetEzsignfoldersignerassociationsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetEzsignformfieldgroupsV1**
> EzsignfolderGetEzsignformfieldgroupsV1Response ezsignfolderGetEzsignformfieldgroupsV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetEzsignformfieldgroupsV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetEzsignformfieldgroupsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetEzsignsignaturesAutomaticV1**
> EzsignfolderGetEzsignsignaturesAutomaticV1Response ezsignfolderGetEzsignsignaturesAutomaticV1()

Return the Ezsignsignatures that can be signed by the current user at the current step in the process

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetEzsignsignaturesAutomaticV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetEzsignsignaturesAutomaticV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetEzsignsignaturesV1**
> EzsignfolderGetEzsignsignaturesV1Response ezsignfolderGetEzsignsignaturesV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetEzsignsignaturesV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetEzsignsignaturesV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetFormsDataV1**
> EzsignfolderGetFormsDataV1Response ezsignfolderGetFormsDataV1()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetFormsDataV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetFormsDataV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/zip


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetListV1**
> EzsignfolderGetListV1Response ezsignfolderGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsignfolderStep | Unsent<br>Sent<br>PartiallySigned<br>Expired<br>Completed<br>Archived<br>Disposed| | eEzsignfoldertypePrivacylevel | User<br>Usergroup | | eEzsignfolderSource | Normal<br>Ezsignbulksend<br>Ezsigntemplatepublic |  Advanced filters that can be used in query parameter *sFilter*:  | Variable | |---| | fkiUserID | | sContactFirstname | | sContactLastname | | sUserFirstname | | sUserLastname | | sEzsigndocumentName |

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let eOrderBy: 'pkiEzsignfolderID_ASC' | 'pkiEzsignfolderID_DESC' | 'sEzsignfolderDescription_ASC' | 'sEzsignfolderDescription_DESC' | 'dtCreatedDate_ASC' | 'dtCreatedDate_DESC' | 'fkiEzsignfoldertypeID_ASC' | 'fkiEzsignfoldertypeID_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'eEzsignfolderStep_ASC' | 'eEzsignfolderStep_DESC' | 'eEzsignfolderCompletion_ASC' | 'eEzsignfolderCompletion_DESC' | 'dtEzsignfolderSentdate_ASC' | 'dtEzsignfolderSentdate_DESC' | 'dtEzsignfolderDuedate_ASC' | 'dtEzsignfolderDuedate_DESC' | 'iEzsigndocument_ASC' | 'iEzsigndocument_DESC' | 'iEzsigndocumentEdm_ASC' | 'iEzsigndocumentEdm_DESC' | 'iEzsignsignature_ASC' | 'iEzsignsignature_DESC' | 'iEzsignsignatureSigned_ASC' | 'iEzsignsignatureSigned_DESC' | 'iEzsignformfieldgroup_ASC' | 'iEzsignformfieldgroup_DESC' | 'iEzsignformfieldgroupCompleted_ASC' | 'iEzsignformfieldgroupCompleted_DESC' | 'dEzsignfolderCompletedpercentage_ASC' | 'dEzsignfolderCompletedpercentage_DESC' | 'dEzsignfolderFormcompletedpercentage_ASC' | 'dEzsignfolderFormcompletedpercentage_DESC' | 'dEzsignfolderSignaturecompletedpercentage_ASC' | 'dEzsignfolderSignaturecompletedpercentage_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiEzsignfolderID_ASC&#39; | &#39;pkiEzsignfolderID_DESC&#39; | &#39;sEzsignfolderDescription_ASC&#39; | &#39;sEzsignfolderDescription_DESC&#39; | &#39;dtCreatedDate_ASC&#39; | &#39;dtCreatedDate_DESC&#39; | &#39;fkiEzsignfoldertypeID_ASC&#39; | &#39;fkiEzsignfoldertypeID_DESC&#39; | &#39;sEzsignfoldertypeNameX_ASC&#39; | &#39;sEzsignfoldertypeNameX_DESC&#39; | &#39;eEzsignfolderStep_ASC&#39; | &#39;eEzsignfolderStep_DESC&#39; | &#39;eEzsignfolderCompletion_ASC&#39; | &#39;eEzsignfolderCompletion_DESC&#39; | &#39;dtEzsignfolderSentdate_ASC&#39; | &#39;dtEzsignfolderSentdate_DESC&#39; | &#39;dtEzsignfolderDuedate_ASC&#39; | &#39;dtEzsignfolderDuedate_DESC&#39; | &#39;iEzsigndocument_ASC&#39; | &#39;iEzsigndocument_DESC&#39; | &#39;iEzsigndocumentEdm_ASC&#39; | &#39;iEzsigndocumentEdm_DESC&#39; | &#39;iEzsignsignature_ASC&#39; | &#39;iEzsignsignature_DESC&#39; | &#39;iEzsignsignatureSigned_ASC&#39; | &#39;iEzsignsignatureSigned_DESC&#39; | &#39;iEzsignformfieldgroup_ASC&#39; | &#39;iEzsignformfieldgroup_DESC&#39; | &#39;iEzsignformfieldgroupCompleted_ASC&#39; | &#39;iEzsignformfieldgroupCompleted_DESC&#39; | &#39;dEzsignfolderCompletedpercentage_ASC&#39; | &#39;dEzsignfolderCompletedpercentage_DESC&#39; | &#39;dEzsignfolderFormcompletedpercentage_ASC&#39; | &#39;dEzsignfolderFormcompletedpercentage_DESC&#39; | &#39;dEzsignfolderSignaturecompletedpercentage_ASC&#39; | &#39;dEzsignfolderSignaturecompletedpercentage_DESC&#39;**]**Array<&#39;pkiEzsignfolderID_ASC&#39; &#124; &#39;pkiEzsignfolderID_DESC&#39; &#124; &#39;sEzsignfolderDescription_ASC&#39; &#124; &#39;sEzsignfolderDescription_DESC&#39; &#124; &#39;dtCreatedDate_ASC&#39; &#124; &#39;dtCreatedDate_DESC&#39; &#124; &#39;fkiEzsignfoldertypeID_ASC&#39; &#124; &#39;fkiEzsignfoldertypeID_DESC&#39; &#124; &#39;sEzsignfoldertypeNameX_ASC&#39; &#124; &#39;sEzsignfoldertypeNameX_DESC&#39; &#124; &#39;eEzsignfolderStep_ASC&#39; &#124; &#39;eEzsignfolderStep_DESC&#39; &#124; &#39;eEzsignfolderCompletion_ASC&#39; &#124; &#39;eEzsignfolderCompletion_DESC&#39; &#124; &#39;dtEzsignfolderSentdate_ASC&#39; &#124; &#39;dtEzsignfolderSentdate_DESC&#39; &#124; &#39;dtEzsignfolderDuedate_ASC&#39; &#124; &#39;dtEzsignfolderDuedate_DESC&#39; &#124; &#39;iEzsigndocument_ASC&#39; &#124; &#39;iEzsigndocument_DESC&#39; &#124; &#39;iEzsigndocumentEdm_ASC&#39; &#124; &#39;iEzsigndocumentEdm_DESC&#39; &#124; &#39;iEzsignsignature_ASC&#39; &#124; &#39;iEzsignsignature_DESC&#39; &#124; &#39;iEzsignsignatureSigned_ASC&#39; &#124; &#39;iEzsignsignatureSigned_DESC&#39; &#124; &#39;iEzsignformfieldgroup_ASC&#39; &#124; &#39;iEzsignformfieldgroup_DESC&#39; &#124; &#39;iEzsignformfieldgroupCompleted_ASC&#39; &#124; &#39;iEzsignformfieldgroupCompleted_DESC&#39; &#124; &#39;dEzsignfolderCompletedpercentage_ASC&#39; &#124; &#39;dEzsignfolderCompletedpercentage_DESC&#39; &#124; &#39;dEzsignfolderFormcompletedpercentage_ASC&#39; &#124; &#39;dEzsignfolderFormcompletedpercentage_DESC&#39; &#124; &#39;dEzsignfolderSignaturecompletedpercentage_ASC&#39; &#124; &#39;dEzsignfolderSignaturecompletedpercentage_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzsignfolderGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetObjectV1**
> EzsignfolderGetObjectV1Response ezsignfolderGetObjectV1()


### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetObjectV1(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetObjectV2**
> EzsignfolderGetObjectV2Response ezsignfolderGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetObjectV2(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderGetObjectV3**
> EzsignfolderGetObjectV3Response ezsignfolderGetObjectV3()



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfolderGetObjectV3(
    pkiEzsignfolderID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderGetObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderImportEzsignfoldersignerassociationsV1**
> EzsignfolderImportEzsignfoldersignerassociationsV1Response ezsignfolderImportEzsignfoldersignerassociationsV1(ezsignfolderImportEzsignfoldersignerassociationsV1Request)



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderImportEzsignfoldersignerassociationsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderImportEzsignfoldersignerassociationsV1Request: EzsignfolderImportEzsignfoldersignerassociationsV1Request; //

const { status, data } = await apiInstance.ezsignfolderImportEzsignfoldersignerassociationsV1(
    pkiEzsignfolderID,
    ezsignfolderImportEzsignfoldersignerassociationsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderImportEzsignfoldersignerassociationsV1Request** | **EzsignfolderImportEzsignfoldersignerassociationsV1Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderImportEzsignfoldersignerassociationsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**403** | The request is not allowed to be executed. Look for detail about the error in the body |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderImportEzsigntemplatepackageV1**
> EzsignfolderImportEzsigntemplatepackageV1Response ezsignfolderImportEzsigntemplatepackageV1(ezsignfolderImportEzsigntemplatepackageV1Request)

This endpoint imports all of the Ezsigntemplates from the Ezsigntemplatepackage into the Ezsignfolder as Ezsigndocuments.  This allows to automatically apply all the Ezsigntemplateformfieldgroups and Ezsigntemplatesignatures on the newly created Ezsigndocuments in a single step.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderImportEzsigntemplatepackageV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderImportEzsigntemplatepackageV1Request: EzsignfolderImportEzsigntemplatepackageV1Request; //

const { status, data } = await apiInstance.ezsignfolderImportEzsigntemplatepackageV1(
    pkiEzsignfolderID,
    ezsignfolderImportEzsigntemplatepackageV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderImportEzsigntemplatepackageV1Request** | **EzsignfolderImportEzsigntemplatepackageV1Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderImportEzsigntemplatepackageV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderImportEzsigntemplatepackageV2**
> EzsignfolderImportEzsigntemplatepackageV2Response ezsignfolderImportEzsigntemplatepackageV2(ezsignfolderImportEzsigntemplatepackageV2Request)

This endpoint imports all of the Ezsigntemplates from the Ezsigntemplatepackage into the Ezsignfolder as Ezsigndocuments.  This allows to automatically apply all the Ezsigntemplateformfieldgroups and Ezsigntemplatesignatures on the newly created Ezsigndocuments in a single step.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderImportEzsigntemplatepackageV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderImportEzsigntemplatepackageV2Request: EzsignfolderImportEzsigntemplatepackageV2Request; //

const { status, data } = await apiInstance.ezsignfolderImportEzsigntemplatepackageV2(
    pkiEzsignfolderID,
    ezsignfolderImportEzsigntemplatepackageV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderImportEzsigntemplatepackageV2Request** | **EzsignfolderImportEzsigntemplatepackageV2Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderImportEzsigntemplatepackageV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderImportEzsigntemplatepackageV3**
> EzsignfolderImportEzsigntemplatepackageV3Response ezsignfolderImportEzsigntemplatepackageV3(ezsignfolderImportEzsigntemplatepackageV3Request)

This endpoint imports all of the Ezsigntemplates from the Ezsigntemplatepackage into the Ezsignfolder as Ezsigndocuments.  This allows to automatically apply all the Ezsigntemplateformfieldgroups and Ezsigntemplatesignatures on the newly created Ezsigndocuments in a single step.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderImportEzsigntemplatepackageV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderImportEzsigntemplatepackageV3Request: EzsignfolderImportEzsigntemplatepackageV3Request; //

const { status, data } = await apiInstance.ezsignfolderImportEzsigntemplatepackageV3(
    pkiEzsignfolderID,
    ezsignfolderImportEzsigntemplatepackageV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderImportEzsigntemplatepackageV3Request** | **EzsignfolderImportEzsigntemplatepackageV3Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderImportEzsigntemplatepackageV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderReorderV2**
> EzsignfolderReorderV2Response ezsignfolderReorderV2(ezsignfolderReorderV2Request)


### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderReorderV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderReorderV2Request: EzsignfolderReorderV2Request; //

const { status, data } = await apiInstance.ezsignfolderReorderV2(
    pkiEzsignfolderID,
    ezsignfolderReorderV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderReorderV2Request** | **EzsignfolderReorderV2Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderReorderV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderSendV1**
> EzsignfolderSendV1Response ezsignfolderSendV1(ezsignfolderSendV1Request)



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderSendV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderSendV1Request: EzsignfolderSendV1Request; //

const { status, data } = await apiInstance.ezsignfolderSendV1(
    pkiEzsignfolderID,
    ezsignfolderSendV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderSendV1Request** | **EzsignfolderSendV1Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderSendV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderSendV3**
> EzsignfolderSendV3Response ezsignfolderSendV3(ezsignfolderSendV3Request)



### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration,
    EzsignfolderSendV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let ezsignfolderSendV3Request: EzsignfolderSendV3Request; //

const { status, data } = await apiInstance.ezsignfolderSendV3(
    pkiEzsignfolderID,
    ezsignfolderSendV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfolderSendV3Request** | **EzsignfolderSendV3Request**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderSendV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfolderUnsendV1**
> EzsignfolderUnsendV1Response ezsignfolderUnsendV1(body)

Once an Ezsignfolder has been sent to signatories, it cannot be modified.  Using this endpoint, you can unsend the Ezsignfolder and make it modifiable again.  Signatories will receive an email informing them the signature process was aborted and they might receive a new invitation to sign.  ⚠️ Warning: Any signature previously made by signatories on \"Non-completed\" Ezsigndocuments will be lost.

### Example

```typescript
import {
    ObjectEzsignfolderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfolderApi(configuration);

let pkiEzsignfolderID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsignfolderUnsendV1(
    pkiEzsignfolderID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsignfolderID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfolderUnsendV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


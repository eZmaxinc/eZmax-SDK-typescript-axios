# ObjectInscriptiontempApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**inscriptiontempGetCommunicationCountV1**](#inscriptiontempgetcommunicationcountv1) | **GET** /1/object/inscriptiontemp/{pkiInscriptiontempID}/getCommunicationCount | Retrieve Communication count|
|[**inscriptiontempGetCommunicationListV1**](#inscriptiontempgetcommunicationlistv1) | **GET** /1/object/inscriptiontemp/{pkiInscriptiontempID}/getCommunicationList | Retrieve Communication list|
|[**inscriptiontempGetCommunicationrecipientsV1**](#inscriptiontempgetcommunicationrecipientsv1) | **GET** /1/object/inscriptiontemp/{pkiInscriptiontempID}/getCommunicationrecipients | Retrieve Inscriptiontemp\&#39;s Communicationrecipient|
|[**inscriptiontempGetCommunicationsendersV1**](#inscriptiontempgetcommunicationsendersv1) | **GET** /1/object/inscriptiontemp/{pkiInscriptiontempID}/getCommunicationsenders | Retrieve Inscriptiontemp\&#39;s Communicationsender|
|[**inscriptiontempGetListV1**](#inscriptiontempgetlistv1) | **GET** /1/object/inscriptiontemp/getList | Retrieve Inscriptiontemp list|
|[**inscriptiontempImportIntoEDMV1**](#inscriptiontempimportintoedmv1) | **POST** /1/object/inscriptiontemp/{pkiInscriptiontempID}/importIntoEDM | Import attachments into the Inscriptiontemp|

# **inscriptiontempGetCommunicationCountV1**
> InscriptiontempGetCommunicationCountV1Response inscriptiontempGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectInscriptiontempApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptiontempApi(configuration);

let pkiInscriptiontempID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptiontempGetCommunicationCountV1(
    pkiInscriptiontempID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptiontempID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptiontempGetCommunicationCountV1Response**

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

# **inscriptiontempGetCommunicationListV1**
> InscriptiontempGetCommunicationListV1Response inscriptiontempGetCommunicationListV1()



### Example

```typescript
import {
    ObjectInscriptiontempApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptiontempApi(configuration);

let pkiInscriptiontempID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptiontempGetCommunicationListV1(
    pkiInscriptiontempID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptiontempID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptiontempGetCommunicationListV1Response**

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

# **inscriptiontempGetCommunicationrecipientsV1**
> InscriptiontempGetCommunicationrecipientsV1Response inscriptiontempGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectInscriptiontempApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptiontempApi(configuration);

let pkiInscriptiontempID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptiontempGetCommunicationrecipientsV1(
    pkiInscriptiontempID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptiontempID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptiontempGetCommunicationrecipientsV1Response**

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

# **inscriptiontempGetCommunicationsendersV1**
> InscriptiontempGetCommunicationsendersV1Response inscriptiontempGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectInscriptiontempApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptiontempApi(configuration);

let pkiInscriptiontempID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptiontempGetCommunicationsendersV1(
    pkiInscriptiontempID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptiontempID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptiontempGetCommunicationsendersV1Response**

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

# **inscriptiontempGetListV1**
> InscriptiontempGetListV1Response inscriptiontempGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eInscriptiontempStatus | Imported<br>Processed<br>Modified |

### Example

```typescript
import {
    ObjectInscriptiontempApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptiontempApi(configuration);

let eOrderBy: 'pkiInscriptiontempID_ASC' | 'pkiInscriptiontempID_DESC' | 'eInscriptiontempStatus_ASC' | 'eInscriptiontempStatus_DESC' | 'sInscriptiontempMLS_ASC' | 'sInscriptiontempMLS_DESC' | 'sInscriptiontempDescription_ASC' | 'sInscriptiontempDescription_DESC' | 'bInscriptiontempIsactive_ASC' | 'bInscriptiontempIsactive_DESC' | 'dtCreatedDate_ASC' | 'dtCreatedDate_DESC' | 'dtModifiedDate_ASC' | 'dtModifiedDate_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.inscriptiontempGetListV1(
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
| **eOrderBy** | [**&#39;pkiInscriptiontempID_ASC&#39; | &#39;pkiInscriptiontempID_DESC&#39; | &#39;eInscriptiontempStatus_ASC&#39; | &#39;eInscriptiontempStatus_DESC&#39; | &#39;sInscriptiontempMLS_ASC&#39; | &#39;sInscriptiontempMLS_DESC&#39; | &#39;sInscriptiontempDescription_ASC&#39; | &#39;sInscriptiontempDescription_DESC&#39; | &#39;bInscriptiontempIsactive_ASC&#39; | &#39;bInscriptiontempIsactive_DESC&#39; | &#39;dtCreatedDate_ASC&#39; | &#39;dtCreatedDate_DESC&#39; | &#39;dtModifiedDate_ASC&#39; | &#39;dtModifiedDate_DESC&#39;**]**Array<&#39;pkiInscriptiontempID_ASC&#39; &#124; &#39;pkiInscriptiontempID_DESC&#39; &#124; &#39;eInscriptiontempStatus_ASC&#39; &#124; &#39;eInscriptiontempStatus_DESC&#39; &#124; &#39;sInscriptiontempMLS_ASC&#39; &#124; &#39;sInscriptiontempMLS_DESC&#39; &#124; &#39;sInscriptiontempDescription_ASC&#39; &#124; &#39;sInscriptiontempDescription_DESC&#39; &#124; &#39;bInscriptiontempIsactive_ASC&#39; &#124; &#39;bInscriptiontempIsactive_DESC&#39; &#124; &#39;dtCreatedDate_ASC&#39; &#124; &#39;dtCreatedDate_DESC&#39; &#124; &#39;dtModifiedDate_ASC&#39; &#124; &#39;dtModifiedDate_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**InscriptiontempGetListV1Response**

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

# **inscriptiontempImportIntoEDMV1**
> InscriptiontempImportIntoEDMV1Response inscriptiontempImportIntoEDMV1(inscriptiontempImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectInscriptiontempApi,
    Configuration,
    InscriptiontempImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptiontempApi(configuration);

let pkiInscriptiontempID: number; // (default to undefined)
let inscriptiontempImportIntoEDMV1Request: InscriptiontempImportIntoEDMV1Request; //

const { status, data } = await apiInstance.inscriptiontempImportIntoEDMV1(
    pkiInscriptiontempID,
    inscriptiontempImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **inscriptiontempImportIntoEDMV1Request** | **InscriptiontempImportIntoEDMV1Request**|  | |
| **pkiInscriptiontempID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptiontempImportIntoEDMV1Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


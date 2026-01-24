# ObjectOtherincomeApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**otherincomeGetCommunicationCountV1**](#otherincomegetcommunicationcountv1) | **GET** /1/object/otherincome/{pkiOtherincomeID}/getCommunicationCount | Retrieve Communication count|
|[**otherincomeGetCommunicationListV1**](#otherincomegetcommunicationlistv1) | **GET** /1/object/otherincome/{pkiOtherincomeID}/getCommunicationList | Retrieve Communication list|
|[**otherincomeGetCommunicationrecipientsV1**](#otherincomegetcommunicationrecipientsv1) | **GET** /1/object/otherincome/{pkiOtherincomeID}/getCommunicationrecipients | Retrieve Otherincome\&#39;s Communicationrecipient|
|[**otherincomeGetCommunicationsendersV1**](#otherincomegetcommunicationsendersv1) | **GET** /1/object/otherincome/{pkiOtherincomeID}/getCommunicationsenders | Retrieve Otherincome\&#39;s Communicationsender|
|[**otherincomeGetListV1**](#otherincomegetlistv1) | **GET** /1/object/otherincome/getList | Retrieve Otherincome list|
|[**otherincomeImportIntoEDMV1**](#otherincomeimportintoedmv1) | **POST** /1/object/otherincome/{pkiOtherincomeID}/importIntoEDM | Import attachments into the Otherincome|

# **otherincomeGetCommunicationCountV1**
> OtherincomeGetCommunicationCountV1Response otherincomeGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectOtherincomeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOtherincomeApi(configuration);

let pkiOtherincomeID: number; // (default to undefined)

const { status, data } = await apiInstance.otherincomeGetCommunicationCountV1(
    pkiOtherincomeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOtherincomeID** | [**number**] |  | defaults to undefined|


### Return type

**OtherincomeGetCommunicationCountV1Response**

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

# **otherincomeGetCommunicationListV1**
> OtherincomeGetCommunicationListV1Response otherincomeGetCommunicationListV1()



### Example

```typescript
import {
    ObjectOtherincomeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOtherincomeApi(configuration);

let pkiOtherincomeID: number; // (default to undefined)

const { status, data } = await apiInstance.otherincomeGetCommunicationListV1(
    pkiOtherincomeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOtherincomeID** | [**number**] |  | defaults to undefined|


### Return type

**OtherincomeGetCommunicationListV1Response**

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

# **otherincomeGetCommunicationrecipientsV1**
> OtherincomeGetCommunicationrecipientsV1Response otherincomeGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectOtherincomeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOtherincomeApi(configuration);

let pkiOtherincomeID: number; // (default to undefined)

const { status, data } = await apiInstance.otherincomeGetCommunicationrecipientsV1(
    pkiOtherincomeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOtherincomeID** | [**number**] |  | defaults to undefined|


### Return type

**OtherincomeGetCommunicationrecipientsV1Response**

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

# **otherincomeGetCommunicationsendersV1**
> OtherincomeGetCommunicationsendersV1Response otherincomeGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectOtherincomeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOtherincomeApi(configuration);

let pkiOtherincomeID: number; // (default to undefined)

const { status, data } = await apiInstance.otherincomeGetCommunicationsendersV1(
    pkiOtherincomeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiOtherincomeID** | [**number**] |  | defaults to undefined|


### Return type

**OtherincomeGetCommunicationsendersV1Response**

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

# **otherincomeGetListV1**
> OtherincomeGetListV1Response otherincomeGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eOtherincomeRemunerationtype | Dollars<br>DollarsTaxesIncluded |

### Example

```typescript
import {
    ObjectOtherincomeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOtherincomeApi(configuration);

let eOrderBy: 'pkiOtherincomeID_ASC' | 'pkiOtherincomeID_DESC' | 'fkiOtherincometypeID_ASC' | 'fkiOtherincometypeID_DESC' | 'sOtherincometypeDescriptionX_ASC' | 'sOtherincometypeDescriptionX_DESC' | 'sOtherincomeDescription_ASC' | 'sOtherincomeDescription_DESC' | 'eOtherincomeRemunerationtype_ASC' | 'eOtherincomeRemunerationtype_DESC' | 'dOtherincomeRemunerationsubtotal_ASC' | 'dOtherincomeRemunerationsubtotal_DESC' | 'dOtherincomeRemunerationtaxes_ASC' | 'dOtherincomeRemunerationtaxes_DESC' | 'dOtherincomeRemunerationtotal_ASC' | 'dOtherincomeRemunerationtotal_DESC' | 'dtOtherincomePaid_ASC' | 'dtOtherincomePaid_DESC' | 'bOtherincomeIsactive_ASC' | 'bOtherincomeIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.otherincomeGetListV1(
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
| **eOrderBy** | [**&#39;pkiOtherincomeID_ASC&#39; | &#39;pkiOtherincomeID_DESC&#39; | &#39;fkiOtherincometypeID_ASC&#39; | &#39;fkiOtherincometypeID_DESC&#39; | &#39;sOtherincometypeDescriptionX_ASC&#39; | &#39;sOtherincometypeDescriptionX_DESC&#39; | &#39;sOtherincomeDescription_ASC&#39; | &#39;sOtherincomeDescription_DESC&#39; | &#39;eOtherincomeRemunerationtype_ASC&#39; | &#39;eOtherincomeRemunerationtype_DESC&#39; | &#39;dOtherincomeRemunerationsubtotal_ASC&#39; | &#39;dOtherincomeRemunerationsubtotal_DESC&#39; | &#39;dOtherincomeRemunerationtaxes_ASC&#39; | &#39;dOtherincomeRemunerationtaxes_DESC&#39; | &#39;dOtherincomeRemunerationtotal_ASC&#39; | &#39;dOtherincomeRemunerationtotal_DESC&#39; | &#39;dtOtherincomePaid_ASC&#39; | &#39;dtOtherincomePaid_DESC&#39; | &#39;bOtherincomeIsactive_ASC&#39; | &#39;bOtherincomeIsactive_DESC&#39;**]**Array<&#39;pkiOtherincomeID_ASC&#39; &#124; &#39;pkiOtherincomeID_DESC&#39; &#124; &#39;fkiOtherincometypeID_ASC&#39; &#124; &#39;fkiOtherincometypeID_DESC&#39; &#124; &#39;sOtherincometypeDescriptionX_ASC&#39; &#124; &#39;sOtherincometypeDescriptionX_DESC&#39; &#124; &#39;sOtherincomeDescription_ASC&#39; &#124; &#39;sOtherincomeDescription_DESC&#39; &#124; &#39;eOtherincomeRemunerationtype_ASC&#39; &#124; &#39;eOtherincomeRemunerationtype_DESC&#39; &#124; &#39;dOtherincomeRemunerationsubtotal_ASC&#39; &#124; &#39;dOtherincomeRemunerationsubtotal_DESC&#39; &#124; &#39;dOtherincomeRemunerationtaxes_ASC&#39; &#124; &#39;dOtherincomeRemunerationtaxes_DESC&#39; &#124; &#39;dOtherincomeRemunerationtotal_ASC&#39; &#124; &#39;dOtherincomeRemunerationtotal_DESC&#39; &#124; &#39;dtOtherincomePaid_ASC&#39; &#124; &#39;dtOtherincomePaid_DESC&#39; &#124; &#39;bOtherincomeIsactive_ASC&#39; &#124; &#39;bOtherincomeIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**OtherincomeGetListV1Response**

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

# **otherincomeImportIntoEDMV1**
> OtherincomeImportIntoEDMV1Response otherincomeImportIntoEDMV1(otherincomeImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectOtherincomeApi,
    Configuration,
    OtherincomeImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectOtherincomeApi(configuration);

let pkiOtherincomeID: number; // (default to undefined)
let otherincomeImportIntoEDMV1Request: OtherincomeImportIntoEDMV1Request; //

const { status, data } = await apiInstance.otherincomeImportIntoEDMV1(
    pkiOtherincomeID,
    otherincomeImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **otherincomeImportIntoEDMV1Request** | **OtherincomeImportIntoEDMV1Request**|  | |
| **pkiOtherincomeID** | [**number**] |  | defaults to undefined|


### Return type

**OtherincomeImportIntoEDMV1Response**

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


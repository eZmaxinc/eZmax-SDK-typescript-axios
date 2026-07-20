# ObjectWebhookApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**webhookCreateObjectV2**](#webhookcreateobjectv2) | **POST** /2/object/webhook | Create a new Webhook|
|[**webhookDeleteObjectV1**](#webhookdeleteobjectv1) | **DELETE** /1/object/webhook/{pkiWebhookID} | Delete an existing Webhook|
|[**webhookEditObjectV1**](#webhookeditobjectv1) | **PUT** /1/object/webhook/{pkiWebhookID} | Edit an existing Webhook|
|[**webhookGetHistoryV1**](#webhookgethistoryv1) | **GET** /1/object/webhook/{pkiWebhookID}/getHistory | Retrieve the logs for recent Webhook calls|
|[**webhookGetListV1**](#webhookgetlistv1) | **GET** /1/object/webhook/getList | Retrieve Webhook list|
|[**webhookGetObjectV2**](#webhookgetobjectv2) | **GET** /2/object/webhook/{pkiWebhookID} | Retrieve an existing Webhook|
|[**webhookRegenerateApikeyV1**](#webhookregenerateapikeyv1) | **POST** /1/object/webhook/{pkiWebhookID}/regenerateApikey | Regenerate the Apikey|
|[**webhookSendWebhookV1**](#webhooksendwebhookv1) | **POST** /1/object/webhook/sendWebhook | Emit a Webhook event|
|[**webhookTestV1**](#webhooktestv1) | **POST** /1/object/webhook/{pkiWebhookID}/test | Test the Webhook by calling the Url|

# **webhookCreateObjectV2**
> WebhookCreateObjectV2Response webhookCreateObjectV2(webhookCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration,
    WebhookCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let webhookCreateObjectV2Request: WebhookCreateObjectV2Request; //

const { status, data } = await apiInstance.webhookCreateObjectV2(
    webhookCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **webhookCreateObjectV2Request** | **WebhookCreateObjectV2Request**|  | |


### Return type

**WebhookCreateObjectV2Response**

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

# **webhookDeleteObjectV1**
> WebhookDeleteObjectV1Response webhookDeleteObjectV1()



### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let pkiWebhookID: number; // (default to undefined)

const { status, data } = await apiInstance.webhookDeleteObjectV1(
    pkiWebhookID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiWebhookID** | [**number**] |  | defaults to undefined|


### Return type

**WebhookDeleteObjectV1Response**

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

# **webhookEditObjectV1**
> WebhookEditObjectV1Response webhookEditObjectV1(webhookEditObjectV1Request)



### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration,
    WebhookEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let pkiWebhookID: number; // (default to undefined)
let webhookEditObjectV1Request: WebhookEditObjectV1Request; //

const { status, data } = await apiInstance.webhookEditObjectV1(
    pkiWebhookID,
    webhookEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **webhookEditObjectV1Request** | **WebhookEditObjectV1Request**|  | |
| **pkiWebhookID** | [**number**] |  | defaults to undefined|


### Return type

**WebhookEditObjectV1Response**

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

# **webhookGetHistoryV1**
> WebhookGetHistoryV1Response webhookGetHistoryV1()



### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let pkiWebhookID: number; // (default to undefined)
let eWebhookHistoryinterval: 'LastDay' | 'LastWeek'; //The number of days to return (default to undefined)

const { status, data } = await apiInstance.webhookGetHistoryV1(
    pkiWebhookID,
    eWebhookHistoryinterval
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiWebhookID** | [**number**] |  | defaults to undefined|
| **eWebhookHistoryinterval** | [**&#39;LastDay&#39; | &#39;LastWeek&#39;**]**Array<&#39;LastDay&#39; &#124; &#39;LastWeek&#39;>** | The number of days to return | defaults to undefined|


### Return type

**WebhookGetHistoryV1Response**

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
|**429** | Too Many Requests |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **webhookGetListV1**
> WebhookGetListV1Response webhookGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eWebhookModule | Ezsign<br>Management | | eWebhookEzsignevent | DocumentCompleted<br>FolderCompleted | | eWebhookManagementevent | UserCreated |

### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let eOrderBy: 'pkiWebhookID_ASC' | 'pkiWebhookID_DESC' | 'sWebhookDescription_ASC' | 'sWebhookDescription_DESC' | 'eWebhookEzsignevent_ASC' | 'eWebhookEzsignevent_DESC' | 'eWebhookManagementevent_ASC' | 'eWebhookManagementevent_DESC' | 'eWebhookRealestateevent_ASC' | 'eWebhookRealestateevent_DESC' | 'eWebhookModule_ASC' | 'eWebhookModule_DESC' | 'sWebhookEmailfailed_ASC' | 'sWebhookEmailfailed_DESC' | 'sWebhookEvent_ASC' | 'sWebhookEvent_DESC' | 'sWebhookUrl_ASC' | 'sWebhookUrl_DESC' | 'bWebhookIsactive_ASC' | 'bWebhookIsactive_DESC' | 'bWebhookIssigned_ASC' | 'bWebhookIssigned_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.webhookGetListV1(
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
| **eOrderBy** | [**&#39;pkiWebhookID_ASC&#39; | &#39;pkiWebhookID_DESC&#39; | &#39;sWebhookDescription_ASC&#39; | &#39;sWebhookDescription_DESC&#39; | &#39;eWebhookEzsignevent_ASC&#39; | &#39;eWebhookEzsignevent_DESC&#39; | &#39;eWebhookManagementevent_ASC&#39; | &#39;eWebhookManagementevent_DESC&#39; | &#39;eWebhookRealestateevent_ASC&#39; | &#39;eWebhookRealestateevent_DESC&#39; | &#39;eWebhookModule_ASC&#39; | &#39;eWebhookModule_DESC&#39; | &#39;sWebhookEmailfailed_ASC&#39; | &#39;sWebhookEmailfailed_DESC&#39; | &#39;sWebhookEvent_ASC&#39; | &#39;sWebhookEvent_DESC&#39; | &#39;sWebhookUrl_ASC&#39; | &#39;sWebhookUrl_DESC&#39; | &#39;bWebhookIsactive_ASC&#39; | &#39;bWebhookIsactive_DESC&#39; | &#39;bWebhookIssigned_ASC&#39; | &#39;bWebhookIssigned_DESC&#39;**]**Array<&#39;pkiWebhookID_ASC&#39; &#124; &#39;pkiWebhookID_DESC&#39; &#124; &#39;sWebhookDescription_ASC&#39; &#124; &#39;sWebhookDescription_DESC&#39; &#124; &#39;eWebhookEzsignevent_ASC&#39; &#124; &#39;eWebhookEzsignevent_DESC&#39; &#124; &#39;eWebhookManagementevent_ASC&#39; &#124; &#39;eWebhookManagementevent_DESC&#39; &#124; &#39;eWebhookRealestateevent_ASC&#39; &#124; &#39;eWebhookRealestateevent_DESC&#39; &#124; &#39;eWebhookModule_ASC&#39; &#124; &#39;eWebhookModule_DESC&#39; &#124; &#39;sWebhookEmailfailed_ASC&#39; &#124; &#39;sWebhookEmailfailed_DESC&#39; &#124; &#39;sWebhookEvent_ASC&#39; &#124; &#39;sWebhookEvent_DESC&#39; &#124; &#39;sWebhookUrl_ASC&#39; &#124; &#39;sWebhookUrl_DESC&#39; &#124; &#39;bWebhookIsactive_ASC&#39; &#124; &#39;bWebhookIsactive_DESC&#39; &#124; &#39;bWebhookIssigned_ASC&#39; &#124; &#39;bWebhookIssigned_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**WebhookGetListV1Response**

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

# **webhookGetObjectV2**
> WebhookGetObjectV2Response webhookGetObjectV2()



### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let pkiWebhookID: number; // (default to undefined)

const { status, data } = await apiInstance.webhookGetObjectV2(
    pkiWebhookID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiWebhookID** | [**number**] |  | defaults to undefined|


### Return type

**WebhookGetObjectV2Response**

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

# **webhookRegenerateApikeyV1**
> WebhookRegenerateApikeyV1Response webhookRegenerateApikeyV1(webhookRegenerateApikeyV1Request)



### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration,
    WebhookRegenerateApikeyV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let pkiWebhookID: number; // (default to undefined)
let webhookRegenerateApikeyV1Request: WebhookRegenerateApikeyV1Request; //

const { status, data } = await apiInstance.webhookRegenerateApikeyV1(
    pkiWebhookID,
    webhookRegenerateApikeyV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **webhookRegenerateApikeyV1Request** | **WebhookRegenerateApikeyV1Request**|  | |
| **pkiWebhookID** | [**number**] |  | defaults to undefined|


### Return type

**WebhookRegenerateApikeyV1Response**

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

# **webhookSendWebhookV1**
> WebhookSendWebhookV1Response webhookSendWebhookV1(webhookSendWebhookV1Request)


### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration,
    WebhookSendWebhookV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let webhookSendWebhookV1Request: WebhookSendWebhookV1Request; //

const { status, data } = await apiInstance.webhookSendWebhookV1(
    webhookSendWebhookV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **webhookSendWebhookV1Request** | **WebhookSendWebhookV1Request**|  | |


### Return type

**WebhookSendWebhookV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **webhookTestV1**
> WebhookTestV1Response webhookTestV1(body)



### Example

```typescript
import {
    ObjectWebhookApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectWebhookApi(configuration);

let pkiWebhookID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.webhookTestV1(
    pkiWebhookID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiWebhookID** | [**number**] |  | defaults to undefined|


### Return type

**WebhookTestV1Response**

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


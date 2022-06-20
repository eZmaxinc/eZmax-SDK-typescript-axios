/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponseGetList } from './common-response-get-list';
import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
import { EzsigntemplateGetListV1ResponseAllOf } from './ezsigntemplate-get-list-v1-response-all-of';
import { EzsigntemplateGetListV1ResponseMPayload } from './ezsigntemplate-get-list-v1-response-mpayload';

/**
 * @type EzsigntemplateGetListV1Response
 * Response for GET /1/object/ezsigntemplate/getList
 * @export
 */
export type EzsigntemplateGetListV1Response = CommonResponseGetList & EzsigntemplateGetListV1ResponseAllOf;


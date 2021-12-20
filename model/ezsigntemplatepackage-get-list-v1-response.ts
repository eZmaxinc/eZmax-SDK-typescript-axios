/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponseGetList } from './common-response-get-list';
import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
import { EzsigntemplatepackageGetListV1ResponseAllOf } from './ezsigntemplatepackage-get-list-v1-response-all-of';
import { EzsigntemplatepackageGetListV1ResponseMPayload } from './ezsigntemplatepackage-get-list-v1-response-mpayload';

/**
 * @type EzsigntemplatepackageGetListV1Response
 * Response for the /1/object/ezsigntemplatepackage/getList API Request
 * @export
 */
export type EzsigntemplatepackageGetListV1Response = CommonResponseGetList & EzsigntemplatepackageGetListV1ResponseAllOf;



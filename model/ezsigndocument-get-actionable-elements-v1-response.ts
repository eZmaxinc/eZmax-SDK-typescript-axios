/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponse } from './common-response';
import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
import { EzsigndocumentGetActionableElementsV1ResponseAllOf } from './ezsigndocument-get-actionable-elements-v1-response-all-of';
import { EzsigndocumentGetActionableElementsV1ResponseMPayload } from './ezsigndocument-get-actionable-elements-v1-response-mpayload';

/**
 * @type EzsigndocumentGetActionableElementsV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getActionableElements
 * @export
 */
export type EzsigndocumentGetActionableElementsV1Response = CommonResponse & EzsigndocumentGetActionableElementsV1ResponseAllOf;



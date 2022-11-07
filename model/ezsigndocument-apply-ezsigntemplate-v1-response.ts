/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

import { DefaultObject } from '../base'

/**
 * @type EzsigndocumentApplyEzsigntemplateV1Response
 * Response for POST /1/object/ezsigndocument/{pkiEzsigndocument}/applyEzsigntemplate
 * @export
 */
export type EzsigndocumentApplyEzsigntemplateV1Response = CommonResponse;


/**
 * @export 
 * A EzsigndocumentApplyEzsigntemplateV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigndocumentApplyEzsigntemplateV1Response
 */
export class DefaultObjectEzsigndocumentApplyEzsigntemplateV1Response extends DefaultObject {
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



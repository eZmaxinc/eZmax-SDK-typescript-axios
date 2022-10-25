/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
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
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf } from './ezsignbulksendtransmission-get-forms-data-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload } from './ezsignbulksendtransmission-get-forms-data-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksendtransmissionGetFormsDataV1Response
 * Response for GET /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getFormsData
 * @export
 */
export type EzsignbulksendtransmissionGetFormsDataV1Response = CommonResponse & EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf;


/**
 * @export 
 * A EzsignbulksendtransmissionGetFormsDataV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendtransmissionGetFormsDataV1Response
 */
export class DefaultObjectEzsignbulksendtransmissionGetFormsDataV1Response extends DefaultObject {
   mPayload:Partial<EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



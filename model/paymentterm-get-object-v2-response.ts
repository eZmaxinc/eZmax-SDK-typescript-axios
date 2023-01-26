/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { PaymenttermGetObjectV2ResponseAllOf } from './paymentterm-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { PaymenttermGetObjectV2ResponseMPayload } from './paymentterm-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type PaymenttermGetObjectV2Response
 * Response for GET /2/object/paymentterm/{pkiPaymenttermID}
 * @export
 */
export type PaymenttermGetObjectV2Response = CommonResponse & PaymenttermGetObjectV2ResponseAllOf;


/**
 * @export 
 * A PaymenttermGetObjectV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectPaymenttermGetObjectV2Response
 */
export class DefaultObjectPaymenttermGetObjectV2Response extends DefaultObject {
   mPayload:Partial<PaymenttermGetObjectV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



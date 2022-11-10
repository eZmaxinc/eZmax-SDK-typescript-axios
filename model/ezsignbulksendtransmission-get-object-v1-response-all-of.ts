/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionGetObjectV1ResponseMPayload } from './ezsignbulksendtransmission-get-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignbulksendtransmissionGetObjectV1ResponseAllOf
 */
export interface EzsignbulksendtransmissionGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendtransmissionGetObjectV1ResponseMPayload}
     * @memberof EzsignbulksendtransmissionGetObjectV1ResponseAllOf
     */
    'mPayload': EzsignbulksendtransmissionGetObjectV1ResponseMPayload;
}
/**
 * A EzsignbulksendtransmissionGetObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendtransmissionGetObjectV1ResponseAllOf
 */
export class DefaultObjectEzsignbulksendtransmissionGetObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignbulksendtransmissionGetObjectV1ResponseMPayload> = {}
}



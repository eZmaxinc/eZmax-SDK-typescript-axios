/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload } from './ezsignbulksendtransmission-get-forms-data-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf
 */
export interface EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload}
     * @memberof EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf
     */
    'mPayload': EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload;
}
/**
 * A EzsignbulksendtransmissionGetFormsDataV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendtransmissionGetFormsDataV1ResponseAllOf
 */
export class DefaultObjectEzsignbulksendtransmissionGetFormsDataV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload> = {}
}



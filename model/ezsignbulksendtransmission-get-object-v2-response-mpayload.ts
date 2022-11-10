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
import { EzsignbulksendtransmissionResponseCompound } from './ezsignbulksendtransmission-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /2/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}
 * @export
 * @interface EzsignbulksendtransmissionGetObjectV2ResponseMPayload
 */
export interface EzsignbulksendtransmissionGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignbulksendtransmissionResponseCompound}
     * @memberof EzsignbulksendtransmissionGetObjectV2ResponseMPayload
     */
    'objEzsignbulksendtransmission': EzsignbulksendtransmissionResponseCompound;
}
/**
 * A EzsignbulksendtransmissionGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload
 */
export class DefaultObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload extends DefaultObject {
   objEzsignbulksendtransmission:Partial<EzsignbulksendtransmissionResponseCompound> = {}
}



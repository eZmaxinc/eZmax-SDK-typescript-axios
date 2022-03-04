/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.5
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsignbulksendtransmissionResponseCompound } from './ezsignbulksendtransmission-response-compound';

/**
 * Payload for the /1/object/ezsignbulksend/{pkiEzsignbulksend}/getEzsignbulksendtransmissions API Request
 * @export
 * @interface EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload
 */
export interface EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignbulksendtransmissionResponseCompound>}
     * @memberof EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload
     */
    'a_objEzsignbulksendtransmission': Array<EzsignbulksendtransmissionResponseCompound>;
}


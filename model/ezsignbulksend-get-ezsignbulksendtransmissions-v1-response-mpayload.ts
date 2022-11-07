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
import { EzsignbulksendtransmissionResponseCompound } from './ezsignbulksendtransmission-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /1/object/ezsignbulksend/{pkiEzsignbulksend}/getEzsignbulksendtransmissions
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
/**
 * A EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload
 */
export class DefaultObjectEzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload extends DefaultObject {
   a_objEzsignbulksendtransmission:Array<EzsignbulksendtransmissionResponseCompound> = []
}



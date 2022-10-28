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
import { EzsignsignatureResponseCompound } from './ezsignsignature-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /2/object/ezsignsignature/{pkiEzsignsignatureID}
 * @export
 * @interface EzsignsignatureGetObjectV2ResponseMPayload
 */
export interface EzsignsignatureGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignsignatureResponseCompound}
     * @memberof EzsignsignatureGetObjectV2ResponseMPayload
     */
    'objEzsignsignature': EzsignsignatureResponseCompound;
}
/**
 * A EzsignsignatureGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignatureGetObjectV2ResponseMPayload
 */
export class DefaultObjectEzsignsignatureGetObjectV2ResponseMPayload extends DefaultObject {
   objEzsignsignature:Partial<EzsignsignatureResponseCompound> = {}
}



/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignsignatureSignV1ResponseAllOf
 */
export interface EzsignsignatureSignV1ResponseAllOf {
    /**
     * Payload for POST /1/object/ezsignsignature/{pkiEzsignsignatureID}/sign
     * @type {object}
     * @memberof EzsignsignatureSignV1ResponseAllOf
     */
    'mPayload': object;
}
/**
 * A EzsignsignatureSignV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignatureSignV1ResponseAllOf
 */
export class DefaultObjectEzsignsignatureSignV1ResponseAllOf extends DefaultObject {
   mPayload:object = {}
}



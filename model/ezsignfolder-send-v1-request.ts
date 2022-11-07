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



import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/send
 * @export
 * @interface EzsignfolderSendV1Request
 */
export interface EzsignfolderSendV1Request {
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfolderSendV1Request
     */
    'tExtraMessage': string;
}
/**
 * A EzsignfolderSendV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderSendV1Request
 */
export class DefaultObjectEzsignfolderSendV1Request extends DefaultObject {
   tExtraMessage:string = ''
}



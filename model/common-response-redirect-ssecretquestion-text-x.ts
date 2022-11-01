/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * 352 Redirect Message containing secret question
 * @export
 * @interface CommonResponseRedirectSSecretquestionTextX
 */
export interface CommonResponseRedirectSSecretquestionTextX {
    /**
     * The text of the Secretquestion in the language of the requester
     * @type {string}
     * @memberof CommonResponseRedirectSSecretquestionTextX
     */
    'sSecretquestionTextX': string;
}
/**
 * A CommonResponseRedirectSSecretquestionTextX Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonResponseRedirectSSecretquestionTextX
 */
export class DefaultObjectCommonResponseRedirectSSecretquestionTextX extends DefaultObject {
   sSecretquestionTextX:string = ''
}



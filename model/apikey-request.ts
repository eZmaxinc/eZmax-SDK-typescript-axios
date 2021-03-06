/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.46
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { MultilingualApikeyDescription } from './multilingual-apikey-description';

/**
 * An Apikey Object
 * @export
 * @interface ApikeyRequest
 */
export interface ApikeyRequest {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ApikeyRequest
     */
    fkiUserID: number;
    /**
     * 
     * @type {MultilingualApikeyDescription}
     * @memberof ApikeyRequest
     */
    objApikeyDescription: MultilingualApikeyDescription;
}



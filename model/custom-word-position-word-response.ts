/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CustomWordPositionOccurenceResponse } from './custom-word-position-occurence-response';

/**
 * A Word Position Object
 * @export
 * @interface CustomWordPositionWordResponse
 */
export interface CustomWordPositionWordResponse {
    /**
     * The searched word
     * @type {string}
     * @memberof CustomWordPositionWordResponse
     */
    'sWord': string;
    /**
     * The found occurences for the seached word
     * @type {Array<CustomWordPositionOccurenceResponse>}
     * @memberof CustomWordPositionWordResponse
     */
    'a_objWordPositionOccurence': Array<CustomWordPositionOccurenceResponse>;
}


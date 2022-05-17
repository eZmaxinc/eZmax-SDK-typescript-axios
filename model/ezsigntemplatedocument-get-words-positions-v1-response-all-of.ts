/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CustomWordPositionWordResponse } from './custom-word-position-word-response';

/**
 * 
 * @export
 * @interface EzsigntemplatedocumentGetWordsPositionsV1ResponseAllOf
 */
export interface EzsigntemplatedocumentGetWordsPositionsV1ResponseAllOf {
    /**
     * Payload for POST /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getWordsPositions
     * @type {Array<CustomWordPositionWordResponse>}
     * @memberof EzsigntemplatedocumentGetWordsPositionsV1ResponseAllOf
     */
    'mPayload': Array<CustomWordPositionWordResponse>;
}


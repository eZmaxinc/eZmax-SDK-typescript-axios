/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.2
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
 * @interface EzsigndocumentGetWordsPositionsV1ResponseAllOf
 */
export interface EzsigndocumentGetWordsPositionsV1ResponseAllOf {
    /**
     * Payload for the /1/object/ezsigndocument/{pkiEzsigndocumentID}/getWordsPositions API Request
     * @type {Array<CustomWordPositionWordResponse>}
     * @memberof EzsigndocumentGetWordsPositionsV1ResponseAllOf
     */
    'mPayload': Array<CustomWordPositionWordResponse>;
}


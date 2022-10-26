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


// May contain unused imports in some cases
// @ts-ignore
import { CustomWordPositionWordResponse } from './custom-word-position-word-response';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigndocumentGetWordsPositionsV1ResponseAllOf
 */
export interface EzsigndocumentGetWordsPositionsV1ResponseAllOf {
    /**
     * Payload for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/getWordsPositions
     * @type {Array<CustomWordPositionWordResponse>}
     * @memberof EzsigndocumentGetWordsPositionsV1ResponseAllOf
     */
    'mPayload': Array<CustomWordPositionWordResponse>;
}
/**
 * A EzsigndocumentGetWordsPositionsV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetWordsPositionsV1ResponseAllOf
 */
export class DefaultObjectEzsigndocumentGetWordsPositionsV1ResponseAllOf extends DefaultObject {
   mPayload:Array<CustomWordPositionWordResponse> = []
}



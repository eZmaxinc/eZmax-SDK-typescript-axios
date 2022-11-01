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


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { CustomWordPositionWordResponse } from './custom-word-position-word-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetWordsPositionsV1ResponseAllOf } from './ezsigndocument-get-words-positions-v1-response-all-of';

import { DefaultObject } from '../base'

/**
 * @type EzsigndocumentGetWordsPositionsV1Response
 * Response for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/getWordsPositions
 * @export
 */
export type EzsigndocumentGetWordsPositionsV1Response = CommonResponse & EzsigndocumentGetWordsPositionsV1ResponseAllOf;


/**
 * @export 
 * A EzsigndocumentGetWordsPositionsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigndocumentGetWordsPositionsV1Response
 */
export class DefaultObjectEzsigndocumentGetWordsPositionsV1Response extends DefaultObject {
   mPayload:Array<CustomWordPositionWordResponse> = []
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



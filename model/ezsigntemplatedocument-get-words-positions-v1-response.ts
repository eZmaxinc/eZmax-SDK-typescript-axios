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
import { EzsigntemplatedocumentGetWordsPositionsV1ResponseAllOf } from './ezsigntemplatedocument-get-words-positions-v1-response-all-of';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatedocumentGetWordsPositionsV1Response
 * Response for POST /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getWordsPositions
 * @export
 */
export type EzsigntemplatedocumentGetWordsPositionsV1Response = CommonResponse & EzsigntemplatedocumentGetWordsPositionsV1ResponseAllOf;


/**
 * @export 
 * A EzsigntemplatedocumentGetWordsPositionsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatedocumentGetWordsPositionsV1Response
 */
export class DefaultObjectEzsigntemplatedocumentGetWordsPositionsV1Response extends DefaultObject {
   mPayload:Array<CustomWordPositionWordResponse> = []
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


